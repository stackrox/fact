use std::path::PathBuf;

use anyhow::bail;
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use log::info;
use tokio::{io::unix::AsyncFd, sync::watch::Receiver, task::JoinHandle};

use crate::{client::Client, event::Event};

pub mod bindings;

use bindings::{event_t, path_cfg_t};

pub struct Bpf {
    // The Ebpf object needs to live for as long as we want to keep the
    // programs loaded
    #[allow(dead_code)]
    obj: Ebpf,
    pub fd: AsyncFd<RingBuf<MapData>>,
}

impl Bpf {
    pub fn new(paths: &[PathBuf]) -> anyhow::Result<Self> {
        Bpf::bump_memlock_rlimit()?;

        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        let mut obj = aya::EbpfLoader::new()
            .set_global("paths_len", &(paths.len() as u32), true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/main.o"
            )))?;

        let ringbuf = match obj.take_map("rb") {
            Some(r) => r,
            None => bail!("Ring buffer not found"),
        };
        let ringbuf = RingBuf::try_from(ringbuf)?;
        let fd = AsyncFd::new(ringbuf)?;

        let paths_map = obj.take_map("paths_map").unwrap();
        let mut paths_map: Array<MapData, path_cfg_t> = Array::try_from(paths_map)?;
        let mut path_cfg = path_cfg_t::new();
        for (i, p) in paths.iter().enumerate() {
            info!("Monitoring: {p:?}");
            path_cfg.set(p.to_str().unwrap());
            paths_map.set(i as u32, path_cfg, 0)?;
        }

        let btf = Btf::from_sys_fs()?;
        let trace_file_open: &mut Lsm = obj.program_mut("trace_file_open").unwrap().try_into()?;
        trace_file_open.load("file_open", &btf)?;
        trace_file_open.attach()?;

        Ok(Bpf { obj, fd })
    }

    fn bump_memlock_rlimit() -> anyhow::Result<()> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            bail!("remove limit on locked memory failed, ret is: {ret}");
        }
        Ok(())
    }

    // Gather events from the ring buffer and print them out.
    pub fn start_worker(
        mut client: Option<Client>,
        mut fd: AsyncFd<RingBuf<MapData>>,
        paths: Vec<PathBuf>,
        mut ctx: Receiver<bool>,
    ) -> JoinHandle<()> {
        info!("Starting BPF worker...");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    guard = fd.readable_mut() => {
                        let mut guard = guard.unwrap();
                        let ringbuf = guard.get_inner_mut();
                        while let Some(event) = ringbuf.next() {
                            let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                            let event: Event = event.try_into().unwrap();

                            if paths.is_empty() || paths.iter().any(|p| event.filename.starts_with(p)) {
                                println!("{event:?}");
                                if let Some(client) = client.as_mut() {
                                    let _ = client.send(event).await;
                                }
                            }
                        }
                        guard.clear_ready();
                    },
                    _ = ctx.changed() => {
                        if !*ctx.borrow() {
                            info!("Stopping BPF worker...");
                            return;
                        }
                    },
                }
            }
        })
    }
}
