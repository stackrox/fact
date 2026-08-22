use std::io;

use anyhow::{Context, bail};
use aya::{
    Btf, Ebpf,
    maps::{HashMap, LpmTrie, MapData, PerCpuArray, RingBuf},
    programs::{Program, lsm::LsmLink},
};
use checks::Checks;
use libc::c_char;
use log::{error, info, warn};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, watch},
    task::JoinSet,
};

use crate::{
    config::{BpfConfig, PathsConfig},
    event::Event,
    host_info,
    metrics::EventCounter,
};

use fact_ebpf::{LPM_SIZE_MAX, event_t, inode_key_t, inode_value_t, metrics_t, path_prefix_t};

mod checks;

const RINGBUFFER_NAME: &str = "rb";

pub struct Bpf {
    obj: Ebpf,
    checks: Checks,

    tx: mpsc::Sender<Event>,

    paths_config: watch::Receiver<PathsConfig>,
    paths_lpm_map: LpmTrie<MapData, [c_char; LPM_SIZE_MAX as usize], c_char>,

    links: Vec<LsmLink>,

    running: watch::Receiver<bool>,
    metrics: EventCounter,
}

impl Bpf {
    pub fn new(
        paths_config: watch::Receiver<PathsConfig>,
        bpf_config: &BpfConfig,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Event>)> {
        Bpf::bump_memlock_rlimit()?;

        let btf = Btf::from_sys_fs()?;
        let checks = Checks::new(&btf)?;

        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        let mut obj = Bpf::load_ebpf(&checks, bpf_config)?;

        Bpf::validate_config(&obj, bpf_config);
        let paths_lpm_map = Bpf::take_path_prefix(&mut obj);

        let (tx, rx) = mpsc::channel(100);
        let mut bpf = Bpf {
            obj,
            checks,
            tx,
            paths_config,
            paths_lpm_map,
            links: Vec::new(),
            running,
            metrics,
        };

        bpf.load_progs(&btf, bpf_config)?;
        bpf.load_paths()?;

        Ok((bpf, rx))
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

    fn load_ebpf(checks: &Checks, bpf_config: &BpfConfig) -> anyhow::Result<Ebpf> {
        // Include the BPF object as raw bytes at compile-time and load it
        // at runtime.
        aya::EbpfLoader::new()
            .override_global("host_mount_ns", &host_info::get_host_mount_ns(), true)
            .override_global(
                "path_hooks_support_bpf_d_path",
                &(checks.path_hooks_support_bpf_d_path as u8),
                true,
            )
            .map_max_entries(RINGBUFFER_NAME, bpf_config.ringbuf_size() * 1024)
            .map_max_entries("inode_map", bpf_config.inodes_max())
            .map_max_entries("d_instantiate_ctx", bpf_config.d_instantiate_ctx_size())
            .load(fact_ebpf::EBPF_OBJ)
            .context("failed to load eBPF object")
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

    fn take_path_prefix(
        obj: &mut Ebpf,
    ) -> LpmTrie<MapData, [c_char; LPM_SIZE_MAX as usize], c_char> {
        let Some(paths_lpm_prefix) = obj.take_map("path_prefix") else {
            unreachable!("path_prefix map not found");
        };

        match paths_lpm_prefix.try_into() {
            Ok(map) => map,
            Err(_) => unreachable!("path_prefix map is not LpmTrie"),
        }
    }

    fn take_ringbuffer(&mut self) -> anyhow::Result<RingBuf<MapData>> {
        let ringbuf = match self.obj.take_map(RINGBUFFER_NAME) {
            Some(r) => r,
            None => bail!("Ring buffer not found"),
        };
        Ok(RingBuf::try_from(ringbuf)?)
    }

    fn cleanup_lpm_map(&mut self, new_paths: &[path_prefix_t]) -> anyhow::Result<()> {
        let to_be_removed = self
            .paths_lpm_map
            .keys()
            .filter_map(|p| match p {
                Ok(p) => {
                    let p = path_prefix_t::from(p);
                    if !new_paths.contains(&p) {
                        Some(Ok(p))
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        for p in to_be_removed {
            self.paths_lpm_map.remove(&p.into())?;
        }

        Ok(())
    }

    fn load_paths(&mut self) -> anyhow::Result<()> {
        if self.paths_config.borrow().patterns().is_empty() {
            self.detach_progs();
            self.cleanup_lpm_map(&[])?;
            return Ok(());
        }

        if self.links.is_empty() {
            self.attach_progs()?;
        }

        // Add the new prefixes
        let new_paths = {
            let paths_config = self.paths_config.borrow();
            let patterns = paths_config.patterns();
            let mut new_paths = Vec::with_capacity(patterns.len());
            for p in patterns {
                let prefix = path_prefix_t::try_from(p)?;
                self.paths_lpm_map.insert(&prefix.into(), 0, 0)?;
                new_paths.push(prefix);
            }
            new_paths
        };

        self.cleanup_lpm_map(&new_paths)?;

        Ok(())
    }

    fn load_progs(&mut self, btf: &Btf, bpf_config: &BpfConfig) -> anyhow::Result<()> {
        for (name, prog) in self.obj.programs_mut() {
            // The format used for our hook names is `trace_<hook>`, so
            // we can just strip trace_ to get the hook name we need for
            // loading.
            let Some(hook) = name.strip_prefix("trace_") else {
                bail!("Invalid hook name: {name}");
            };

            if !bpf_config.program_is_enabled(hook) {
                info!("Skipping {hook} loading");
                continue;
            }

            // Skip hooks that the kernel doesn't support
            if self.checks.is_unsupported_hook(hook) {
                info!("Skipping {hook}: not supported on this kernel");
                continue;
            }

            match prog {
                Program::Lsm(prog) => prog.load(hook, btf)?,
                u => unimplemented!("{u:?}"),
            };
        }
        Ok(())
    }

    /// Attaches the supplied BPF program if it is loaded into the kernel.
    fn attach_prog(prog: &mut Program) -> Result<LsmLink, BpfAttachError> {
        match prog {
            Program::Lsm(prog) if prog.fd().is_ok() => {
                let link_id = prog.attach()?;
                Ok(prog.take_link(link_id)?)
            }
            Program::Lsm(_) => Err(BpfAttachError::NotLoaded),
            u => unimplemented!("{u:?}"),
        }
    }

    /// Attaches all loaded BPF programs. Programs that were not loaded
    /// (e.g. optional hooks on unsupported kernels) are skipped.
    ///
    /// If any attach fails, programs that were already attached during
    /// this call are dropped.
    fn attach_progs(&mut self) -> anyhow::Result<()> {
        self.links = self
            .obj
            .programs_mut()
            .filter_map(|(_, prog)| match Bpf::attach_prog(prog) {
                Ok(link) => Some(Ok(link)),
                Err(BpfAttachError::NotLoaded) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, BpfAttachError>>()?;

        Ok(())
    }

    /// Detaches all BPF programs by dropping owned links.
    fn detach_progs(&mut self) {
        self.links.clear();
    }

    /// Verify the current configuration for errors.
    ///
    /// Checks for hooks that are not implemented.
    fn validate_config(obj: &Ebpf, bpf_config: &BpfConfig) -> bool {
        let mut is_valid = true;

        for name in bpf_config.programs.keys() {
            let hook = "trace_".to_string() + name;
            if obj.program(&hook).is_none() {
                warn!("{name} is not a known program");
                is_valid = false;
            }
        }

        is_valid
    }

    // Gather events from the ring buffer and print them out.
    pub fn start(mut self, task_set: &mut JoinSet<anyhow::Result<()>>) {
        info!("Starting BPF worker...");

        task_set.spawn(async move {
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
                                Ok(event) => {
                                    // If the event is monitored by parent, we need to check
                                    // its host path, but we don't have that context here,
                                    // so we let the event go into HostScanner and make the
                                    // decision there.
                                    if !event.is_monitored_by_parent() &&
                                            event.is_ignored(&self.paths_config.borrow().globset) {
                                        self.metrics.dropped();
                                        continue;
                                    }
                                    event
                                },
                                Err(e) => {
                                    error!("Failed to parse event: '{e}'");
                                    self.metrics.dropped();
                                    continue;
                                }
                            };

                            self.metrics.added();
                            if self.tx.send(event).await.is_err() {
                                info!("No BPF consumers left, stopping...");
                                break;
                            }
                        }
                        guard.clear_ready();
                    },
                    _ = self.paths_config.changed() => {
                        self.load_paths().context("Failed to load paths")?;
                    },
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            info!("Stopping BPF worker...");
                            break;
                        }
                    },
                }
            }

            Ok(())
        });
    }
}

#[derive(thiserror::Error, Debug)]
enum BpfAttachError {
    #[error("attempted to attach unloaded program")]
    NotLoaded,
    #[error("program error: {0:?}")]
    ProgramError(#[from] aya::programs::ProgramError),
}

#[cfg(all(test, feature = "bpf-test"))]
mod bpf_tests {
    use std::{collections, env, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

    use tempfile::NamedTempFile;
    use tokio::{sync::watch, time::timeout};

    use crate::{
        config::{BpfProgConfig, FactConfig, reloader::Reloader},
        event::{EventTestData, process::Process},
        host_info,
        metrics::Metrics,
    };

    use super::*;

    #[tokio::test]
    async fn test_basic() {
        if let Ok(value) = std::env::var("FACT_LOGLEVEL") {
            let value = value.to_lowercase();
            if value == "debug" || value == "trace" {
                crate::init_log().unwrap();
            }
        }

        let monitored_path = env!("CARGO_MANIFEST_DIR");
        let monitored_path = PathBuf::from(monitored_path);
        let paths = vec![PathBuf::from(format!("{}/**/*", monitored_path.display()))];
        let mut config = FactConfig::default();
        config.set_paths(paths);
        let bpf_config = config.bpf.clone();
        let reloader = Reloader::try_from(config).unwrap();
        let metrics = Metrics::new();
        let (run_tx, run_rx) = watch::channel(true);
        let (bpf, mut rx) = Bpf::new(
            reloader.paths(),
            &bpf_config,
            run_rx,
            metrics.bpf_worker.clone(),
        )
        .expect("Failed to load BPF code");
        let mut task_set = JoinSet::new();

        bpf.start(&mut task_set);

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Create a file
        let file = NamedTempFile::new_in(&monitored_path).expect("Failed to create temporary file");
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

        // Trigger a file rename
        let renamed_path = monitored_path.join("target");
        std::fs::rename(&file, &renamed_path).expect("Failed to rename file");
        // Move the file back so it can be properly closed
        std::fs::rename(&renamed_path, &file).expect("Failed to rename file");

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
                EventTestData::Rename(file_path.clone()),
                host_info::get_hostname(),
                renamed_path.clone(),
                PathBuf::new(),
                current.clone(),
            )
            .unwrap(),
            Event::new(
                EventTestData::Rename(renamed_path),
                host_info::get_hostname(),
                file_path.clone(),
                PathBuf::new(),
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

        let wait = timeout(Duration::from_secs(1), async move {
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
            res = task_set.join_next() => res.unwrap().unwrap().unwrap(),
        }

        run_tx.send(false).unwrap();
    }

    #[test]
    fn test_validate_config() {
        let tests = [
            (collections::HashMap::new(), true),
            (
                collections::HashMap::from([("file_open".into(), BpfProgConfig::default())]),
                true,
            ),
            (
                collections::HashMap::from([(
                    "file_open".into(),
                    BpfProgConfig {
                        enabled: Some(true),
                    },
                )]),
                true,
            ),
            (
                collections::HashMap::from([(
                    "file_open".into(),
                    BpfProgConfig {
                        enabled: Some(false),
                    },
                )]),
                true,
            ),
            (
                collections::HashMap::from([
                    (
                        "file_open".into(),
                        BpfProgConfig {
                            enabled: Some(false),
                        },
                    ),
                    (
                        "path_rename".into(),
                        BpfProgConfig {
                            enabled: Some(true),
                        },
                    ),
                    ("path_unlink".into(), BpfProgConfig::default()),
                ]),
                true,
            ),
            (
                collections::HashMap::from([("gibberish".into(), BpfProgConfig::default())]),
                false,
            ),
        ];

        let btf = Btf::from_sys_fs().expect("Failed to read BTF symbols");
        let checks = Checks::new(&btf).expect("Failed to create `checks`");
        let obj =
            Bpf::load_ebpf(&checks, &BpfConfig::default()).expect("Failed to load eBPF object");

        for (programs, expected) in tests {
            let mut bpf_config = BpfConfig::default();
            bpf_config.programs = programs.clone();

            let res = Bpf::validate_config(&obj, &bpf_config);

            assert_eq!(res, expected, "input: {programs:#?}");
        }
    }
}
