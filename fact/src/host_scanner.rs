use std::{
    cell::RefCell,
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use aya::maps::MapData;
use fact_ebpf::{inode_key_t, inode_value_t};
use log::{debug, info, warn};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
};

use crate::{bpf::Bpf, event::Event, host_info};

pub struct HostScanner {
    kernel_inode_map: RefCell<aya::maps::HashMap<MapData, inode_key_t, inode_value_t>>,
    inode_map: RefCell<std::collections::HashMap<inode_key_t, PathBuf>>,

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

        // Run an initial scan to fill in the inode map
        host_scanner.scan()?;

        Ok(host_scanner)
    }

    fn scan(&self) -> anyhow::Result<()> {
        debug!("Host scan started");
        for path in self.config.borrow().iter() {
            let path = host_info::prepend_host_mount(path);
            self.scan_inner(&path)?;
        }
        debug!("Host scan done");

        Ok(())
    }

    fn scan_inner(&self, path: &Path) -> anyhow::Result<()> {
        if path.is_dir() {
            for entry in path.read_dir()?.flatten() {
                let entry = entry.path();
                self.scan_inner(&entry)
                    .with_context(|| format!("Failed to scan {}", entry.display()))?;
            }
        } else if path.is_file() {
            self.update_entry(path)
                .with_context(|| format!("Failed to update entry for {}", path.display()))?;
        }
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

        self.kernel_inode_map.borrow_mut().insert(inode, 0, 0)?;
        let mut inode_map = self.inode_map.borrow_mut();
        let entry = inode_map.entry(inode).or_default();
        *entry = host_info::remove_host_mount(path);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    fn get_host_path(&self, inode: &inode_key_t) -> Option<PathBuf> {
        // The path here needs to be cloned because we won't keep the
        // inode_map borrow long enough.
        self.inode_map.borrow().get(inode).cloned()
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Starting host scanner...");

            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(mut event) = event else {
                            info!("No more events to process");
                            break;
                        };

                        if let Some(host_path) = self.get_host_path(event.get_inode()) {
                            event.set_host_path(host_path);
                        }

                        let event = Arc::new(event);
                        if let Err(e) = self.tx.send(event) {
                            warn!("Failed to send event: {e}");
                        }
                    },
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            break;
                        }
                    }
                }
            }

            info!("Stopping host scanner");
            Ok(())
        })
    }
}
