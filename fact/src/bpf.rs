use std::{io, sync::Arc};

use anyhow::{bail, Context};
use aya::{
    maps::{LpmTrie, MapData, PerCpuArray, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use libc::c_char;
use log::{debug, error, info};
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, watch::Receiver},
    task::JoinHandle,
};

use crate::{config::FactConfig, event::Event, host_info, metrics::EventCounter};

use fact_ebpf::{event_t, metrics_t, path_prefix_t, LPM_SIZE_MAX};

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
            .set_global(
                "filter_by_prefix",
                &((!config.paths().is_empty()) as u8),
                true,
            )
            .set_global("host_mount_ns", &host_info::get_host_mount_ns(), true)
            .set_max_entries(RINGBUFFER_NAME, config.ringbuf_size() * 1024)
            .load(fact_ebpf::EBPF_OBJ)?;

        let ringbuf = match obj.take_map(RINGBUFFER_NAME) {
            Some(r) => r,
            None => bail!("Ring buffer not found"),
        };
        let ringbuf = RingBuf::try_from(ringbuf)?;
        let fd = AsyncFd::new(ringbuf)?;

        let Some(path_prefix) = obj.take_map("path_prefix") else {
            bail!("path_prefix map not found");
        };
        let mut path_prefix: LpmTrie<MapData, [c_char; LPM_SIZE_MAX as usize], c_char> =
            LpmTrie::try_from(path_prefix)?;
        for p in config.paths() {
            let prefix = path_prefix_t::try_from(p)?;
            path_prefix.insert(&prefix.into(), 0, 0)?;
        }

        let btf = Btf::from_sys_fs()?;
        let Some(trace_file_open) = obj.program_mut("trace_file_open") else {
            bail!("trace_file_open program not found");
        };
        let trace_file_open: &mut Lsm = trace_file_open.try_into()?;
        trace_file_open.load("file_open", &btf)?;
        trace_file_open.attach()?;

        let Some(trace_path_unlink) = obj.program_mut("trace_path_unlink") else {
            bail!("trace_path_unlink program not found");
        };
        let trace_path_unlink: &mut Lsm = trace_path_unlink.try_into()?;
        trace_path_unlink.load("path_unlink", &btf)?;
        trace_path_unlink.attach()?;

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
        mut running: Receiver<bool>,
        event_counter: EventCounter,
    ) -> JoinHandle<()> {
        info!("Starting BPF worker...");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    guard = fd.readable_mut() => {
                        let mut guard = guard
                            .context("ringbuffer guard held while runtime is stopping")
                            .unwrap();
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

                            event_counter.added();
                            if output.send(event).is_err() {
                                info!("No BPF consumers left, stopping...");
                                return;
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
    use std::{env, path::PathBuf, time::Duration};

    use anyhow::Context;
    use fact_ebpf::file_activity_type_t;
    use tempfile::NamedTempFile;
    use tokio::{sync::watch, time::timeout};

    use crate::{event::process::Process, host_info, metrics::exporter::Exporter};

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
        let mut config = FactConfig::default();
        config.set_paths(paths);
        executor.block_on(async {
            let mut bpf = Bpf::new(&config).expect("Failed to load BPF code");
            let (tx, mut rx) = broadcast::channel(100);
            let (run_tx, run_rx) = watch::channel(true);
            // Create a metrics exporter, but don't start it
            let exporter = Exporter::new(bpf.get_metrics().unwrap());

            Bpf::start_worker(tx, bpf.fd, run_rx, exporter.metrics.bpf_worker.clone());

            // Create a file
            let file =
                NamedTempFile::new_in(monitored_path).expect("Failed to create temporary file");
            println!("Created {file:?}");

            let expected = Event::new(
                file_activity_type_t::FILE_ACTIVITY_CREATION,
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
