use aya::{
    maps::{Array, MapData, RingBuf},
    programs::Lsm,
    Btf,
};
use client::Client;
use config::FactConfig;
use event::Event;
use log::{debug, info};
use tokio::{io::unix::AsyncFd, signal, task::yield_now};

mod bpf;
mod client;
pub mod config;
mod event;
mod host_info;

use bpf::bindings::{event_t, path_cfg_t};

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Include the BPF object as raw bytes at compile-time and load it
    // at runtime.
    let mut bpf = aya::EbpfLoader::new()
        .set_global("paths_len", &(config.paths.len() as u32), true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/main.o"
        )))?;

    // Setup the ring buffer for events.
    let ringbuf = bpf.take_map("rb").unwrap();
    let ringbuf = RingBuf::try_from(ringbuf)?;
    let mut async_fd = AsyncFd::new(ringbuf)?;

    // Setup the map with the paths to be monitored
    let paths_map = bpf.take_map("paths_map").unwrap();
    let mut paths_map: Array<MapData, path_cfg_t> = Array::try_from(paths_map)?;
    let mut path_cfg = path_cfg_t::new();
    for (i, p) in config.paths.iter().enumerate() {
        info!("Monitoring: {p:?}");
        path_cfg.set(p.to_str().unwrap());
        paths_map.set(i as u32, path_cfg, 0)?;
    }

    // Load the programs
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("trace_file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    // Create the gRPC client
    let mut client = if let Some(url) = config.url.as_ref() {
        Some(Client::start(url, config.certs)?)
    } else {
        None
    };

    // Gather events from the ring buffer and print them out.
    tokio::spawn(async move {
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ringbuf = guard.get_inner_mut();
            while let Some(event) = ringbuf.next() {
                let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                let event: Event = event.try_into().unwrap();

                println!("{event:?}");
                if let Some(client) = client.as_mut() {
                    let _ = client.send(event).await;
                }
            }
            guard.clear_ready();
            yield_now().await;
        }
    });

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
