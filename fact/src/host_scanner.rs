//! # Host Scanner module
//!
//! This module is in charge of scanning the host file system and
//! maintaining a mapping of inode and device number to host path.
//!
//! An initial scan of the filesystem is triggered when a `HostScanner`
//! object is first created. The scan will populate two maps:
//! * A HashMap that holds an inode to path translation.
//! * An eBPF HashMap that will let the eBPF programs know if a given
//!   file is being monitored, regardless of the path being used to
//!   access it.
//!
//! Calling the `start` method on the `HostScanner` object will consume
//! it and spawn a new tokio task that will receive events from the
//! provided `mpsc::Receiver<Event>`, update their host paths and send
//! them out its `broadcast::Sender<Arc<Event>>` for further processing.
//!
//! TODO: Implement updating maps based on received events, periodic
//! scans to remediate inconsistencies due to missed events, etc..

use std::{
    cell::RefCell,
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use aya::maps::MapData;
use fact_ebpf::{inode_key_t, inode_value_t};
use log::{debug, info, warn};
use tokio::{
    sync::{Notify, broadcast, mpsc, watch},
    task::JoinHandle,
};

use crate::{
    bpf::Bpf,
    event::Event,
    host_info,
    metrics::host_scanner::{HostScannerMetrics, ScanLabels},
};

pub struct HostScanner {
    kernel_inode_map: RefCell<aya::maps::HashMap<MapData, inode_key_t, inode_value_t>>,
    inode_map: RefCell<std::collections::HashMap<inode_key_t, PathBuf>>,

    paths: watch::Receiver<Vec<PathBuf>>,
    scan_interval: watch::Receiver<Duration>,
    running: watch::Receiver<bool>,

    rx: mpsc::Receiver<Event>,
    tx: broadcast::Sender<Arc<Event>>,

    metrics: HostScannerMetrics,
}

impl HostScanner {
    pub fn new(
        bpf: &mut Bpf,
        rx: mpsc::Receiver<Event>,
        paths: watch::Receiver<Vec<PathBuf>>,
        scan_interval: watch::Receiver<Duration>,
        running: watch::Receiver<bool>,
        metrics: HostScannerMetrics,
    ) -> anyhow::Result<Self> {
        let kernel_inode_map = RefCell::new(bpf.take_inode_map()?);
        let inode_map = RefCell::new(std::collections::HashMap::new());
        let (tx, _) = broadcast::channel(100);

        let host_scanner = HostScanner {
            kernel_inode_map,
            inode_map,
            paths,
            scan_interval,
            running,
            rx,
            tx,
            metrics,
        };

        // Run an initial scan to fill in the inode map
        host_scanner.scan()?;

        Ok(host_scanner)
    }

    fn scan(&self) -> anyhow::Result<()> {
        debug!("Host scan started");
        self.metrics.scan_inc(ScanLabels::Scans);
        let config = self.paths.borrow();

        // Cleanup any items that are either:
        // * Not configured to be monitored anymore.
        // * Are configured to be monitored but no longer are found in
        //   the file system.
        self.inode_map.borrow_mut().retain(|inode, path| {
            if config.iter().any(|prefix| path.starts_with(prefix))
                && host_info::prepend_host_mount(path).exists()
            {
                true
            } else {
                let _ = self.kernel_inode_map.borrow_mut().remove(inode);
                self.metrics.scan_inc(ScanLabels::InodeRemoved);
                false
            }
        });

        for pattern in self.paths.borrow().iter() {
            let path = host_info::prepend_host_mount(pattern);
            self.scan_inner(&path)?;
        }
        debug!("Host scan done");

        Ok(())
    }

    fn scan_inner(&self, path: &Path) -> anyhow::Result<()> {
        self.metrics.scan_inc(ScanLabels::ElementsScanned);

        let Some(glob_str) = path.to_str() else {
            bail!("invalid path {}", path.display());
        };

        for entry in glob::glob(glob_str)? {
            match entry {
                Ok(path) => {
                    if path.is_file() {
                        self.metrics.scan_inc(ScanLabels::FileScanned);
                        self.update_entry(path.as_path()).with_context(|| {
                            format!("Failed to update entry for {}", path.display())
                        })?;
                    } else if path.is_dir() {
                        self.metrics.scan_inc(ScanLabels::DirectoryScanned);
                        self.update_entry(path.as_path()).with_context(|| {
                            format!("Failed to update entry for {}", path.display())
                        })?;
                    } else {
                        self.metrics.scan_inc(ScanLabels::FsItemIgnored);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn update_entry(&self, path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            // If path does not exist, we don't have anything to update
            self.metrics.scan_inc(ScanLabels::FileRemoved);
            return Ok(());
        }

        let metadata = path.metadata()?;
        let inode = inode_key_t {
            inode: metadata.st_ino(),
            dev: metadata.st_dev(),
        };

        let host_path = host_info::remove_host_mount(path);
        self.update_entry_with_inode(&inode, host_path)?;

        debug!("Added entry for {}: {inode:?}", path.display());
        Ok(())
    }

    /// Similar to update_entry except we are are directly using the inode instead of the path.
    fn update_entry_with_inode(&self, inode: &inode_key_t, path: PathBuf) -> anyhow::Result<()> {
        self.kernel_inode_map
            .borrow_mut()
            .insert(*inode, 0, 0)
            .with_context(|| format!("Failed to insert kernel entry for {}", path.display()))?;

        let mut inode_map = self.inode_map.borrow_mut();
        let entry = inode_map.entry(*inode).or_default();
        *entry = path;

        self.metrics.scan_inc(ScanLabels::FileUpdated);

        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    fn get_host_path(&self, inode: Option<&inode_key_t>) -> Option<PathBuf> {
        // The path here needs to be cloned because we won't keep the
        // inode_map borrow long enough.
        self.inode_map.borrow().get(inode?).cloned()
    }

    /// Handle file creation events by adding new inodes to the map.
    ///
    /// We use the parent inode provided by the eBPF code
    /// to look up the parent directory's host path, then construct the full
    /// path by appending the new file's name.
    fn handle_creation_event(&self, event: &Event) -> anyhow::Result<()> {
        let inode = event.get_inode();

        if self.get_host_path(Some(inode)).is_some() {
            return Ok(());
        }

        let parent_inode = event.get_parent_inode();

        if parent_inode.empty() {
            debug!(
                "Creation event has no parent inode: {}",
                event.get_filename().display()
            );
            return Ok(());
        }

        let event_filename = event.get_filename();
        let Some(filename) = event_filename.file_name() else {
            debug!(
                "Creation event has no filename component: {}",
                event_filename.display()
            );
            return Ok(());
        };

        let Some(parent_host_path) = self.get_host_path(Some(parent_inode)) else {
            debug!(
                "Parent inode not in map, cannot construct host path for: {}",
                event_filename.display()
            );
            return Ok(());
        };

        let host_path = parent_host_path.join(filename);

        debug!(
            "Constructed host path for creation event: {} (from container path: {}, parent host path: {})",
            host_path.display(),
            event_filename.display(),
            parent_host_path.display()
        );

        self.update_entry_with_inode(inode, host_path)
            .with_context(|| {
                format!(
                    "Failed to add creation event entry for {}",
                    event_filename.display()
                )
            })?;
        debug!(
            "Successfully added inode entry for newly created file: {}",
            event_filename.display()
        );

        Ok(())
    }

    /// Periodically notify the host scanner main task that a scan needs
    /// to happen.
    ///
    /// This is needed because `tokio::time::Interval::tick` will create
    /// a new future every time it is called, if used in a
    /// `tokio::select` with other events that trigger more often, the
    /// tick will never happen. This way we have a separate task that
    /// will reliably send a notification to the main one.
    fn start_scan_notifier(&self, scan_trigger: Arc<Notify>) {
        let mut running = self.running.clone();
        let mut scan_interval = self.scan_interval.clone();
        tokio::spawn(async move {
            while *running.borrow() {
                let mut interval = tokio::time::interval(*scan_interval.borrow());
                loop {
                    tokio::select! {
                        _ = interval.tick() => scan_trigger.notify_one(),
                        _ = running.changed() => break,
                        _ = scan_interval.changed() => break,
                    }
                }
            }
        });
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        let scan_trigger = Arc::new(Notify::new());
        self.start_scan_notifier(scan_trigger.clone());

        tokio::spawn(async move {
            info!("Starting host scanner...");

            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(mut event) = event else {
                            info!("No more events to process");
                            break;
                        };
                        self.metrics.events.added();

                        // Handle file creation events by adding new inodes to the map
                        if event.is_creation() {
                            if let Err(e) = self.handle_creation_event(&event) {
                                warn!("Failed to handle creation event: {e}");
                            }
                        }

                        if let Some(host_path) = self.get_host_path(Some(event.get_inode())) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_host_path(host_path);
                        }

                        if let Some(host_path) = self.get_host_path(event.get_old_inode()) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_old_host_path(host_path);
                        }

                        let event = Arc::new(event);
                        if let Err(e) = self.tx.send(event) {
                            self.metrics.events.dropped();
                            warn!("Failed to send event: {e}");
                        }
                    },
                    _ = scan_trigger.notified() => self.scan()?,
                    _ = self.paths.changed() => self.scan()?,
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
