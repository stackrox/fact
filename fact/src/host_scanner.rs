use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use aya::maps::MapData;
use aya_obj::generated::BPF_ANY;
use fact_ebpf::{inode_key_t, inode_value_t};
use log::{debug, info, warn};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
    time::interval,
};

use crate::{bpf::Bpf, event::Event, host_info};

pub struct HostScanner {
    kernel_inode_map: RefCell<aya::maps::HashMap<MapData, inode_key_t, inode_value_t>>,
    inode_map: RefCell<HashMap<inode_key_t, HashSet<PathBuf>>>,

    config: watch::Receiver<Vec<PathBuf>>,
    running: watch::Receiver<bool>,

    rx: mpsc::Receiver<Event>,
    tx: broadcast::Sender<Arc<Event>>,
}

impl HostScanner {
    pub fn new(
        bpf: &mut Bpf,
        rx: mpsc::Receiver<Event>,
        config: watch::Receiver<Vec<PathBuf>>,
        running: watch::Receiver<bool>,
    ) -> anyhow::Result<Self> {
        let kernel_inode_map = RefCell::new(bpf.take_inode_map()?);
        let inode_map = RefCell::new(std::collections::HashMap::new());
        let (tx, _) = broadcast::channel(100);

        let host_scanner = HostScanner {
            kernel_inode_map,
            inode_map,
            config,
            running,
            rx,
            tx,
        };

        // Run an initial scan to fill the inode maps.
        host_scanner.scan()?;

        Ok(host_scanner)
    }

    fn scan(&self) -> anyhow::Result<()> {
        debug!("Host scan started...");
        for path in self.config.borrow().iter() {
            let path = host_info::get_host_mount().join(path.strip_prefix("/")?);
            debug!("Scanning {}", path.display());
            for ancestor in path.ancestors() {
                self.update_entry(ancestor)
                    .with_context(|| format!("Failed to update ancestor {}", path.display()))?;

                if ancestor == host_info::get_host_mount() {
                    break;
                }
            }

            if path.is_dir() {
                for entry in (path.read_dir()?).flatten() {
                    self.scan_inner(&entry.path())
                        .with_context(|| format!("Failed to scan {}", path.display()))?;
                }
            } else if path.is_file() {
                self.update_entry(&path)
                    .with_context(|| format!("Failed to update entry for {}", path.display()))?;
            }
        }
        debug!("Host scan done");

        Ok(())
    }

    fn scan_inner(&self, path: &Path) -> anyhow::Result<()> {
        debug!("scanning {}", path.display());
        if path.is_dir() {
            self.update_entry(path)?;

            for path in (path.read_dir()?).flatten() {
                self.scan_inner(&path.path())?;
            }
        } else if path.is_file() {
            self.update_entry(path)?;
        }
        Ok(())
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        debug!("InodeMap cleanup started");
        for (_, paths) in self.inode_map.borrow_mut().iter_mut() {
            paths.retain(|path| {
                self.config
                    .borrow()
                    .iter()
                    .any(|prefix| path.starts_with(prefix) || prefix.starts_with(path))
            });
        }

        self.inode_map.borrow_mut().retain(|inode, paths| {
            if paths.is_empty() {
                if let Err(e) = self.kernel_inode_map.borrow_mut().remove(inode) {
                    warn!("Failed to remove inode from kernel map: {e}");
                }
                false
            } else {
                true
            }
        });

        debug!("InodeMap cleanup done");
        Ok(())
    }

    fn update_entry(&self, path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            // If path does not exist, we don't have anything to update
            return Ok(());
        }

        let metadata = path.metadata()?;
        let inode = inode_key_t {
            inode: metadata.st_ino(),
            dev: metadata.st_dev(),
        };
        debug!("{}: {inode:?}", path.display());
        let path = Path::new("/").join(
            path.strip_prefix(host_info::get_host_mount())
                .context("Failed to remove host mount prefix")?,
        );

        self.kernel_inode_map
            .borrow_mut()
            .insert(inode, 0, BPF_ANY.into())
            .with_context(|| format!("Failed to add inode marker for {}", path.display()))?;
        let mut inode_map = self.inode_map.borrow_mut();
        let entry = inode_map.entry(inode).or_default();
        entry.insert(path.to_path_buf());
        Ok(())
    }

    fn set_host_path(&self, event: &mut Event) {
        let inode_map = self.inode_map.borrow();
        let host_path = if let Some(set) = inode_map.get(event.get_inode()) {
            set.iter().next().unwrap_or(&PathBuf::new()).to_path_buf()
        } else if let Some(set) = inode_map.get(event.get_parent_inode()) {
            // If we got here, there is a file that is under a monitored
            // directory that is not itself monitored, we try to guess
            // its path from the parent.
            //
            // Need to look deeper into if and why this would happen and
            // if other actions should be taken instead.
            set.iter()
                .next()
                .unwrap_or(&PathBuf::new())
                .join(event.get_filename().file_name().unwrap_or_default())
        } else {
            // No inode markers on the file or the parent
            return;
        };

        event.set_host_path(host_path);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    fn handle_file_creation(&self, event: &mut Event) -> anyhow::Result<bool> {
        info!("File creation: {}", event.get_filename().display());
        // The new file is in a monitored directory, update the
        // inode information.
        //
        // This needs to be done in two stages, because we cannot borrow
        // self.inode_map mutably while we are iterating the parent
        // paths.
        let new_entries = {
            let inode_map = self.inode_map.borrow();
            let Some(parent_set) = inode_map.get(event.get_parent_inode()) else {
                // The file is in a directory that is not monitored.
                // Most likely this is a prefix hit from a container.
                return Ok(true);
            };

            let filename = event.get_filename().file_name().unwrap();
            parent_set
                .iter()
                .map(|path| path.join(filename))
                .collect::<Vec<_>>()
        };

        let mut emit_event = false;
        for path in &new_entries {
            info!("paths: {}", path.display());
            if !self
                .config
                .borrow()
                .iter()
                .any(|prefix| path.starts_with(prefix))
            {
                // File is not monitored
                continue;
            }

            emit_event = true;
            if event.get_host_path() == Path::new("") {
                event.set_host_path(path.clone());
            }
            self.update_entry(path)?;
        }

        if !emit_event {
            // If we got here, there is a file marked for monitoring
            // that shouldn't be marked for it. Go through the new
            // entries again and cleanup the inode_map entries for each.
            for path in new_entries {
                if let Err(e) = self.kernel_inode_map.borrow_mut().remove(event.get_inode()) {
                    warn!("Failed to remove inode from path {}: {e}", path.display());
                }
            }
        }
        Ok(emit_event)
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        info!("Starting host scanner...");

        let (tx, mut rx) = mpsc::channel(1);
        let mut running = self.running.clone();

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));
            ticker.tick().await; // Discard the first immediate tick

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        debug!("Triggering scan");
                        tx.send(()).await.expect("Failed to send scan message");
                    }
                    _ = running.changed() => {
                        if !*running.borrow() {
                            return;
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(mut event) = event else {
                            info!("No more events to process");
                            break;
                        };

                        if event.is_creation() {
                            let emit_event = self.handle_file_creation(&mut event)?;
                            if !emit_event {
                                continue;
                            }
                        } else {
                            {
                                let inode_map = self.inode_map.borrow();
                                if !inode_map.contains_key(event.get_inode()) &&
                                    !inode_map.contains_key(event.get_parent_inode()) &&
                                    !self.config.borrow().iter().any(|prefix| event.get_filename().starts_with(prefix)) {
                                    continue;
                                }
                            }
                            self.set_host_path(&mut event);
                        }

                        let event = Arc::new(event);
                        if let Err(e) = self.tx.send(event) {
                            warn!("Failed to send event: {e}");
                        }
                    },
                    _ = rx.recv() => {
                        self.scan()?;
                        self.cleanup()?;
                    },
                    _ = self.config.changed() => {
                        self.scan()?;
                        self.cleanup()?;
                    },
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            break;
                        }
                    },
                }
            }

            info!("Stopping host scanner...");
            Ok(())
        })
    }
}
