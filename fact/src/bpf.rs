use std::{io, path::PathBuf, sync::Arc};

use anyhow::{bail, Context};
use aya::{
    maps::{Array, LpmTrie, MapData, PerCpuArray, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use libc::c_char;
use log::{debug, error, info};
use tokio::{
    io::unix::AsyncFd,
    sync::{broadcast, watch},
    task::JoinHandle,
};

use crate::{event::Event, host_info, metrics::EventCounter};

use fact_ebpf::{event_t, metrics_t, path_prefix_t, LPM_SIZE_MAX};

const RINGBUFFER_NAME: &str = "rb";

pub struct Bpf {
    obj: Ebpf,

    tx: broadcast::Sender<Arc<Event>>,

    paths: Vec<path_prefix_t>,
    paths_config: watch::Receiver<Vec<PathBuf>>,
}

impl Bpf {
    pub fn new(
        paths_config: watch::Receiver<Vec<PathBuf>>,
        ringbuf_size: u32,
    ) -> anyhow::Result<Self> {
        Bpf::bump_memlock_rlimit()?;

        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        let obj = aya::EbpfLoader::new()
            .set_global("host_mount_ns", &host_info::get_host_mount_ns(), true)
            .set_max_entries(RINGBUFFER_NAME, ringbuf_size * 1024)
            .load(fact_ebpf::EBPF_OBJ)?;

        let paths = Vec::new();
        let (tx, _) = broadcast::channel(100);
        let mut bpf = Bpf {
            obj,
            tx,
            paths,
            paths_config,
        };

        bpf.load_paths()?;
        bpf.load_progs()?;

        Ok(bpf)
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

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    pub fn take_metrics(&mut self) -> anyhow::Result<PerCpuArray<MapData, metrics_t>> {
        let metrics = match self.obj.take_map("metrics") {
            Some(m) => m,
            None => bail!("metrics map not found"),
        };
        Ok(PerCpuArray::try_from(metrics)?)
    }

    fn take_ringbuffer(&mut self) -> anyhow::Result<RingBuf<MapData>> {
        let ringbuf = match self.obj.take_map(RINGBUFFER_NAME) {
            Some(r) => r,
            None => bail!("Ring buffer not found"),
        };
        Ok(RingBuf::try_from(ringbuf)?)
    }

    fn load_paths(&mut self) -> anyhow::Result<()> {
        let paths_config = self.paths_config.borrow();
        let Some(filter_by_prefix) = self.obj.map_mut("filter_by_prefix_map") else {
            bail!("filter_by_prefix_map map not found");
        };
        let mut filter_by_prefix: Array<&mut MapData, c_char> = Array::try_from(filter_by_prefix)?;
        filter_by_prefix.set(0, !paths_config.is_empty() as c_char, 0)?;

        let Some(path_prefix) = self.obj.map_mut("path_prefix") else {
            bail!("path_prefix map not found");
        };
        let mut path_prefix: LpmTrie<&mut MapData, [c_char; LPM_SIZE_MAX as usize], c_char> =
            LpmTrie::try_from(path_prefix)?;

        // Add the new prefixes
        let mut new_paths = Vec::with_capacity(paths_config.len());
        for p in paths_config.iter() {
            let prefix = path_prefix_t::try_from(p)?;
            path_prefix.insert(&prefix.into(), 0, 0)?;
            new_paths.push(prefix);
        }

        // Remove old prefixes
        for p in self.paths.iter().filter(|p| !new_paths.contains(p)) {
            path_prefix.remove(&(*p).into())?;
        }

        self.paths = new_paths;

        Ok(())
    }

    fn load_lsm_prog(&mut self, name: &str, hook: &str, btf: &Btf) -> anyhow::Result<()> {
        let Some(prog) = self.obj.program_mut(name) else {
            bail!("{name} program not found");
        };
        let prog: &mut Lsm = prog.try_into()?;
        prog.load(hook, btf)?;
        Ok(())
    }

    fn load_progs(&mut self) -> anyhow::Result<()> {
        let btf = Btf::from_sys_fs()?;
        self.load_lsm_prog("trace_file_open", "file_open", &btf)?;
        self.load_lsm_prog("trace_path_unlink", "path_unlink", &btf)?;
        self.load_lsm_prog("trace_bprm_check", "bprm_check_security", &btf)
    }

    fn attach_progs(&mut self) -> anyhow::Result<()> {
        for (_, prog) in self.obj.programs_mut() {
            let prog: &mut Lsm = prog.try_into()?;
            prog.attach()?;
        }
        Ok(())
    }

    // Gather events from the ring buffer and print them out.
    pub fn start(
        mut self,
        mut running: watch::Receiver<bool>,
        event_counter: EventCounter,
    ) -> JoinHandle<anyhow::Result<()>> {
        info!("Starting BPF worker...");

        tokio::spawn(async move {
            self.attach_progs()
                .context("Failed to attach ebpf programs")?;

            let rb = self.take_ringbuffer()?;
            let mut fd = AsyncFd::new(rb)?;

            loop {
                tokio::select! {
                    guard = fd.readable_mut() => {
                        let mut guard = guard
                            .context("ringbuffer guard held while runtime is stopping")?;
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
                            if self.tx.send(event).is_err() {
                                info!("No BPF consumers left, stopping...");
                                break;
                            }
                        }
                        guard.clear_ready();
                    },
                    _ = self.paths_config.changed() => {
                        self.load_paths().context("Failed to load paths")?;
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            info!("Stopping BPF worker...");
                            break;
                        }
                    },
                }
            }

            Ok(())
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

    use crate::{
        config::{reloader::Reloader, FactConfig},
        event::process::Process,
        host_info,
        metrics::exporter::Exporter,
    };

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
        if let Ok(value) = std::env::var("FACT_LOGLEVEL") {
            let value = value.to_lowercase();
            if value == "debug" || value == "trace" {
                crate::init_log().unwrap();
            }
        }

        let executor = get_executor().unwrap();
        let monitored_path = env!("CARGO_MANIFEST_DIR");
        let monitored_path = PathBuf::from(monitored_path);
        let paths = vec![monitored_path.clone()];
        let mut config = FactConfig::default();
        config.set_paths(paths);
        let reloader = Reloader::from(config);
        executor.block_on(async {
            let mut bpf = Bpf::new(reloader.paths(), reloader.config().ringbuf_size())
                .expect("Failed to load BPF code");
            let mut rx = bpf.subscribe();
            let (run_tx, run_rx) = watch::channel(true);
            // Create a metrics exporter, but don't start it
            let exporter = Exporter::new(bpf.take_metrics().unwrap());

            let handle = bpf.start(run_rx, exporter.metrics.bpf_worker.clone());

            tokio::time::sleep(Duration::from_millis(500)).await;

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
            )
            .unwrap();

            println!("Expected: {expected:?}");
            let wait = timeout(Duration::from_secs(1), async move {
                while let Ok(event) = rx.recv().await {
                    println!("{event:?}");
                    if *event == expected {
                        break;
                    }
                }
            });

            tokio::select! {
                res = wait => res.unwrap(),
                res = handle => res.unwrap().unwrap(),
            }

            run_tx.send(false).unwrap();
        });
    }
}
