use std::{convert::Infallible, net::SocketAddr};

use anyhow::Context;
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::Lsm,
    Btf,
};
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use log::{debug, info};
use tokio::{
    io::unix::AsyncFd,
    net::TcpListener,
    signal::unix::{signal, SignalKind},
    sync::mpsc::channel,
};

mod bpf;
mod client;
pub mod config;
mod event;
mod host_info;
mod pre_flight;

use bpf::bindings::{event_t, path_cfg_t};
use client::Client;
use config::FactConfig;
use event::Event;
use pre_flight::pre_flight;

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    pre_flight().context("Pre-flight checks failed")?;

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

    // At this point the BPF code is in the kernel, we start our
    // healthcheck probe
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], 9000));
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_| async move {
                            Ok::<Response<Full<Bytes>>, Infallible>(Response::new(Full::new(
                                Bytes::from(""),
                            )))
                        }),
                    )
                    .await
                {
                    eprintln!("Error serving connection: {err:?}");
                }
            });
        }
    });

    // Create the gRPC client
    let mut client = if let Some(url) = config.url.as_ref() {
        Some(Client::start(url, config.certs)?)
    } else {
        None
    };

    let (tx, mut rx) = channel(1);

    info!("Starting BPF worker...");
    // Gather events from the ring buffer and print them out.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                guard = async_fd.readable_mut() => {
                    let mut guard = guard.unwrap();
                    let ringbuf = guard.get_inner_mut();
                    while let Some(event) = ringbuf.next() {
                        let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                        let event: Event = event.try_into().unwrap();

                        if config.paths.is_empty() || config.paths.iter().any(|p| event.filename.starts_with(p)) {
                            println!("{event:?}");
                            if let Some(client) = client.as_mut() {
                                let _ = client.send(event).await;
                            }
                        }
                    }
                    guard.clear_ready();
                }
                    _ = rx.recv() => {
                        info!("Stopping BPF worker...");
                        return;
                    }
            }
        }
    });

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    tx.send(()).await?;
    info!("Exiting...");

    Ok(())
}
