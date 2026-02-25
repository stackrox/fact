use std::{
    io,
    os::fd::AsRawFd,
    path::PathBuf,
    thread::{self, JoinHandle},
};

use anyhow::{bail, Context};
use aya::{
    maps::{Array, HashMap, LpmTrie, MapData, PerCpuArray, RingBuf},
    programs::Program,
    Btf, Ebpf,
};
use checks::Checks;
use libc::c_char;
use log::{error, info};
use tokio::sync::{mpsc, watch};

use crate::{event::Event, host_info, metrics::EventCounter};

use fact_ebpf::{event_t, inode_key_t, inode_value_t, metrics_t, path_prefix_t, LPM_SIZE_MAX};

mod checks;

const RINGBUFFER_NAME: &str = "rb";

pub struct Bpf {
    obj: Ebpf,

    tx: mpsc::Sender<Event>,

    paths: Vec<path_prefix_t>,
    paths_config: watch::Receiver<Vec<PathBuf>>,
}

impl Bpf {
    pub fn new(
        paths_config: watch::Receiver<Vec<PathBuf>>,
        ringbuf_size: u32,
        tx: mpsc::Sender<Event>,
    ) -> anyhow::Result<Self> {
        Bpf::bump_memlock_rlimit()?;

        let btf = Btf::from_sys_fs()?;
        let checks = Checks::new(&btf)?;

        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        let obj = aya::EbpfLoader::new()
            .set_global("host_mount_ns", &host_info::get_host_mount_ns(), true)
            .set_global(
                "path_hooks_support_bpf_d_path",
                &(checks.path_hooks_support_bpf_d_path as u8),
                true,
            )
            .set_max_entries(RINGBUFFER_NAME, ringbuf_size * 1024)
            .load(fact_ebpf::EBPF_OBJ)?;

        let paths = Vec::new();
        let mut bpf = Bpf {
            obj,
            tx,
            paths,
            paths_config,
        };

        bpf.load_paths()?;
        bpf.load_progs(&btf)?;

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

    pub fn take_inode_map(
        &mut self,
    ) -> anyhow::Result<HashMap<MapData, inode_key_t, inode_value_t>> {
        let Some(inode_map) = self.obj.take_map("inode_map") else {
            bail!("inode_map not found");
        };
        Ok(inode_map.try_into()?)
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

    fn load_progs(&mut self, btf: &Btf) -> anyhow::Result<()> {
        for (name, prog) in self.obj.programs_mut() {
            // The format used for our hook names is `trace_<hook>`, so
            // we can just strip trace_ to get the hook name we need for
            // loading.
            let Some(hook) = name.strip_prefix("trace_") else {
                bail!("Invalid hook name: {name}");
            };
            match prog {
                Program::Lsm(prog) => prog.load(hook, btf)?,
                u => unimplemented!("{u:?}"),
            }
        }
        Ok(())
    }

    fn attach_progs(&mut self) -> anyhow::Result<()> {
        for (_, prog) in self.obj.programs_mut() {
            match prog {
                Program::Lsm(prog) => prog.attach()?,
                u => unimplemented!("{u:?}"),
            };
        }
        Ok(())
    }

    // Gather events from the ring buffer and print them out.
    pub fn start(
        mut self,
        running: watch::Receiver<bool>,
        event_counter: EventCounter,
    ) -> JoinHandle<anyhow::Result<()>> {
        info!("Starting BPF worker...");

        thread::spawn(move || {
            self.attach_progs()
                .context("Failed to attach ebpf programs")?;

            let mut rb = self.take_ringbuffer()?;

            let rb_event = epoll::Event::new(epoll::Events::EPOLLIN, 0);
            let poller = match epoll::create(false) {
                Ok(p) => p,
                Err(e) => bail!("Failed to create epoll: {e:?}"),
            };
            if let Err(e) = epoll::ctl(
                poller,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                rb.as_raw_fd(),
                rb_event,
            ) {
                bail!("Failed to add ringbuffer to epoll: {e:?}");
            }

            loop {
                if running.has_changed()? && !*running.borrow() {
                    break;
                }

                if self.paths_config.has_changed()? {
                    self.load_paths().context("Failed to load paths")?;
                }

                match epoll::wait(poller, 100, &mut [rb_event]) {
                    Ok(n) if n != 0 => {
                        while let Some(event) = rb.next() {
                            let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                            let event = match Event::try_from(event) {
                                Ok(event) => event,
                                Err(e) => {
                                    error!("Failed to parse event: '{e}'");
                                    event_counter.dropped();
                                    continue;
                                }
                            };

                            event_counter.added();
                            if self.tx.blocking_send(event).is_err() {
                                info!("No BPF consumers left, stopping...");
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => bail!("Failed to wait for ringbuffer events: {e:?}"),
                }
            }

            info!("Stopping BPF worker...");
            Ok(())
        })
    }
}

#[cfg(all(test, feature = "bpf-test"))]
mod bpf_tests {
    use std::{env, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

    use tempfile::NamedTempFile;
    use tokio::{sync::watch, time::timeout};

    use crate::{
        config::{reloader::Reloader, FactConfig},
        event::{process::Process, EventTestData},
        host_info,
        metrics::exporter::Exporter,
    };

    use super::*;

    #[test]
    fn test_basic() {
        if let Ok(value) = std::env::var("FACT_LOGLEVEL") {
            let value = value.to_lowercase();
            if value == "debug" || value == "trace" {
                crate::init_log().unwrap();
            }
        }

        let monitored_path = env!("CARGO_MANIFEST_DIR");
        let monitored_path = PathBuf::from(monitored_path);
        let paths = vec![monitored_path.clone()];
        let mut config = FactConfig::default();
        config.set_paths(paths);
        let reloader = Reloader::from(config);
        let (tx, mut rx) = mpsc::channel(100);
        let mut bpf = Bpf::new(reloader.paths(), reloader.config().ringbuf_size(), tx)
            .expect("Failed to load BPF code");
        let (run_tx, run_rx) = watch::channel(true);
        // Create a metrics exporter, but don't start it
        let exporter = Exporter::new(bpf.take_metrics().unwrap());

        let handle = bpf.start(run_rx, exporter.metrics.bpf_worker.clone());

        thread::sleep(Duration::from_millis(500));

        // Create a file
        let file = NamedTempFile::new_in(monitored_path).expect("Failed to create temporary file");
        println!("Created {file:?}");

        // Trigger permission changes
        let mut perms = file
            .path()
            .metadata()
            .expect("Failed to read file permissions")
            .permissions();
        let old_perm = perms.mode() as u16;
        let new_perm: u16 = 0o666;
        perms.set_mode(new_perm as u32);
        std::fs::set_permissions(file.path(), perms).expect("Failed to set file permissions");

        let current = Process::current();
        let file_path = file.path().to_path_buf();

        let expected_events = [
            Event::new(
                EventTestData::Creation,
                host_info::get_hostname(),
                file_path.clone(),
                PathBuf::new(), // host path is resolved by HostScanner
                current.clone(),
            )
            .unwrap(),
            Event::new(
                EventTestData::Chmod(new_perm, old_perm),
                host_info::get_hostname(),
                file_path.clone(),
                PathBuf::new(), // host path is resolved by HostScanner
                current.clone(),
            )
            .unwrap(),
            Event::new(
                EventTestData::Unlink,
                host_info::get_hostname(),
                file_path,
                PathBuf::new(), // host path is resolved by HostScanner
                current,
            )
            .unwrap(),
        ];

        // Close the file, removing it
        file.close().expect("Failed to close temp file");

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let wait = timeout(Duration::from_secs(1), async {
                for expected in expected_events {
                    println!("expected: {expected:#?}");
                    while let Some(event) = rx.recv().await {
                        println!("{event:#?}");
                        if event == expected {
                            println!("Found!");
                            break;
                        }
                    }
                }
            });

            tokio::select! {
                res = wait => res.unwrap(),
            }
        });

        run_tx.send(false).unwrap();
        handle.join().unwrap().unwrap();
    }
}
