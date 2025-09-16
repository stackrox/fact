use std::{io, path::PathBuf, sync::Arc};

use anyhow::{bail, Context};
use aya::{
    maps::{MapData, PerCpuArray, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use log::{debug, error, info};
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, watch::Receiver},
    task::JoinHandle,
};

use crate::{config::FactConfig, event::Event, host_info, metrics::EventCounter};

pub mod bindings;

use bindings::{event_t, metrics_t};

pub struct Bpf {
    // The Ebpf object needs to live for as long as we want to keep the
    // programs loaded
    #[allow(dead_code)]
    obj: Ebpf,
    pub fd: AsyncFd<RingBuf<MapData>>,
}

impl Bpf {
    pub fn new(config: &FactConfig) -> anyhow::Result<Self> {
        const RINGBUFFER_NAME: &str = "rb";

        Bpf::bump_memlock_rlimit()?;

        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        let mut obj = aya::EbpfLoader::new()
            .set_global("paths_len", &(config.paths().len() as u32), true)
            .set_global("host_mount_ns", &host_info::get_host_mount_ns(), true)
            .set_max_entries(RINGBUFFER_NAME, config.ringbuf_size() * 1024)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/main.o"
            )))?;

        let ringbuf = match obj.take_map(RINGBUFFER_NAME) {
            Some(r) => r,
            None => bail!("Ring buffer not found"),
        };
        let ringbuf = RingBuf::try_from(ringbuf)?;
        let fd = AsyncFd::new(ringbuf)?;

        /* TODO: ROX-30438, re-implement kernel side filtering
        let paths_map = obj.take_map("paths_map").unwrap();
        let mut paths_map: Array<MapData, path_cfg_t> = Array::try_from(paths_map)?;
        let mut path_cfg = path_cfg_t::new();
        for (i, p) in paths.iter().enumerate() {
            info!("Monitoring: {p:?}");
            path_cfg.set(p.to_str().unwrap());
            paths_map.set(i as u32, path_cfg, 0)?;
        }
        */

        let btf = Btf::from_sys_fs()?;
        let trace_file_open: &mut Lsm = obj.program_mut("trace_file_open").unwrap().try_into()?;
        trace_file_open.load("file_open", &btf)?;
        trace_file_open.attach()?;

        Ok(Bpf { obj, fd })
    }

    pub fn get_metrics(&mut self) -> anyhow::Result<PerCpuArray<MapData, metrics_t>> {
        let metrics = match self.obj.take_map("metrics") {
            Some(m) => m,
            None => bail!("metrics map not found"),
        };
        Ok(PerCpuArray::try_from(metrics)?)
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
            bail!(
                "Remove limit on locked memory failed, ret: {ret}, errno: {:?}",
                io::Error::last_os_error()
            );
        }
        Ok(())
    }

    // Gather events from the ring buffer and print them out.
    pub fn start_worker(
        output: broadcast::Sender<Arc<Event>>,
        mut fd: AsyncFd<RingBuf<MapData>>,
        paths: Vec<PathBuf>,
        mut running: Receiver<bool>,
        event_counter: EventCounter,
    ) -> JoinHandle<()> {
        info!("Starting BPF worker...");
        info!("Monitoring: {paths:?}");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    guard = fd.readable_mut() => {
                        let mut guard = guard.unwrap();
                        let ringbuf = guard.get_inner_mut();
                        while let Some(event) = ringbuf.next() {
                            let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                            let event = match Event::try_from(event) {
                                Ok(event) => Arc::new(event),
                                Err(e) => {
                                    error!("Failed to parse event: '{e}'");
                                    debug!("Event: {event:?}");
                                    event_counter.dropped();
                                    continue;
                                }
                            };

                            if paths.is_empty() || paths.iter().any(|p| event.filename.starts_with(p)) {
                                event_counter.added();
                                output
                                    .send(event)
                                    .context("Failed to send event, all receivers exitted")
                                    .unwrap();
                            } else {
                                event_counter.ignored();
                            }
                        }
                        guard.clear_ready();
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            info!("Stopping BPF worker...");
                            return;
                        }
                    },
                }
            }
        })
    }
}

#[cfg(all(test, feature = "bpf-test"))]
mod bpf_tests {
    use std::{env, time::Duration};

    use anyhow::Context;
    use tempfile::NamedTempFile;
    use tokio::{sync::watch, time::timeout};

    use crate::{event::Process, host_info, metrics::exporter::Exporter};

    use super::*;

    fn get_executor() -> anyhow::Result<tokio::runtime::Runtime> {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed building tokio runtime")?;
        Ok(executor)
    }

    #[test]
    fn test_basic() {
        let executor = get_executor().unwrap();
        let monitored_path = env!("CARGO_MANIFEST_DIR");
        let monitored_path = PathBuf::from(monitored_path);
        let paths = vec![monitored_path.clone()];
        let config = FactConfig::default();
        executor.block_on(async {
            let mut bpf = Bpf::new(&config).expect("Failed to load BPF code");
            let (tx, mut rx) = broadcast::channel(100);
            let (run_tx, run_rx) = watch::channel(true);
            // Create a metrics exporter, but don't start it
            let exporter = Exporter::new(bpf.get_metrics().unwrap());

            Bpf::start_worker(
                tx,
                bpf.fd,
                paths,
                run_rx,
                exporter.metrics.bpf_worker.clone(),
            );

            // Create a file
            let file =
                NamedTempFile::new_in(monitored_path).expect("Failed to create temporary file");
            println!("Created {file:?}");

            let expected = Event::new(
                host_info::get_hostname(),
                file.path().to_path_buf(),
                file.path().to_path_buf(),
                Process::current(),
            );

            println!("Expected: {expected:?}");
            timeout(Duration::from_secs(1), async move {
                while let Ok(event) = rx.recv().await {
                    println!("{event:?}");
                    if *event == expected {
                        break;
                    }
                }
            })
            .await
            .unwrap();

            run_tx.send(false).unwrap();
        });
    }
}
