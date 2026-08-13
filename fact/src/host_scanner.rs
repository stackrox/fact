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
    collections::HashMap,
    collections::HashSet,
    fs::Metadata,
    io,
    ops::{Deref, DerefMut},
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use aya::{
    maps::{MapData, MapError},
    sys::SyscallError,
};
use fact_ebpf::{inode_key_t, inode_value_t, monitored_t};
use globset::{Glob, GlobSet, GlobSetBuilder};
use log::{debug, info, warn};
use serde::{Serialize, ser::SerializeMap};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};

use crate::{
    bpf::Bpf,
    event::Event,
    host_info,
    metrics::host_scanner::{HostScannerMetrics, ScanLabels},
};

struct InodeMap(HashMap<inode_key_t, HashSet<PathBuf>>);

impl InodeMap {
    fn new() -> Self {
        InodeMap(HashMap::new())
    }
}

impl Deref for InodeMap {
    type Target = HashMap<inode_key_t, HashSet<PathBuf>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for InodeMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for InodeMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in &self.0 {
            // In order to be able to serialize InodeMap to JSON, we use
            // a string key. This enables us to send this type over HTTP
            // as part of the "/inodes" introspection endpoint, while
            // keeping the existing inode_key_t Serialize implementation.
            map.serialize_entry(&format!("{}:{}", k.dev, k.inode), v)?;
        }
        map.end()
    }
}

pub struct HostScanner {
    kernel_inode_map: RefCell<aya::maps::HashMap<MapData, inode_key_t, inode_value_t>>,
    inode_map: RefCell<InodeMap>,

    paths: watch::Receiver<Vec<PathBuf>>,
    scan_interval: watch::Receiver<Duration>,

    rx: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    introspection: mpsc::Receiver<oneshot::Sender<serde_json::Result<String>>>,

    metrics: HostScannerMetrics,

    paths_globset: GlobSet,
}

impl HostScanner {
    pub fn new(
        bpf: &mut Bpf,
        rx: mpsc::Receiver<Event>,
        paths: watch::Receiver<Vec<PathBuf>>,
        scan_interval: watch::Receiver<Duration>,
        metrics: HostScannerMetrics,
        introspection: mpsc::Receiver<oneshot::Sender<serde_json::Result<String>>>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Event>)> {
        let kernel_inode_map = RefCell::new(bpf.take_inode_map()?);
        let inode_map = RefCell::new(InodeMap::new());
        let (tx, output) = mpsc::channel(100);
        let paths_globset = HostScanner::build_globset(paths.borrow().as_slice())?;

        let host_scanner = HostScanner {
            kernel_inode_map,
            inode_map,
            paths,
            scan_interval,
            rx,
            tx,
            introspection,
            metrics,
            paths_globset,
        };

        // Run an initial scan to fill in the inode map
        host_scanner.scan()?;

        Ok((host_scanner, output))
    }

    fn build_globset(paths: &[PathBuf]) -> anyhow::Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();
        for p in paths.iter() {
            let Some(glob_str) = p.to_str() else {
                bail!("failed to convert path {} to string", p.display());
            };

            builder.add(
                Glob::new(glob_str)
                    .with_context(|| format!("invalid glob {}", glob_str))
                    .unwrap(),
            );
        }
        Ok(builder.build()?)
    }

    fn scan(&self) -> anyhow::Result<()> {
        info!("Host scan started");
        let start = Instant::now();
        self.metrics.scan_inc(ScanLabels::Scans);
        let config = self.paths.borrow();

        // Cleanup any items that are either:
        // * Not configured to be monitored anymore.
        // * Are configured to be monitored but no longer are found in
        //   the file system.
        self.inode_map.borrow_mut().retain(|inode, paths| {
            // Remove paths that no longer exist or are not monitored
            paths.retain(|path| {
                config.iter().any(|prefix| path.starts_with(prefix))
                    && host_info::prepend_host_mount(path).exists()
            });

            // If no monitored paths remain, remove the inode entirely
            if paths.is_empty() {
                let _ = self.kernel_inode_map.borrow_mut().remove(inode);
                self.metrics.scan_inc(ScanLabels::InodeRemoved);
                false
            } else {
                true
            }
        });

        for pattern in self.paths.borrow().iter() {
            let path = host_info::prepend_host_mount(pattern);
            self.scan_inner(&path)?;
        }
        let duration = start.elapsed();
        self.metrics.scan_duration.observe(duration.as_secs_f64());
        info!(
            "Host scan done, took {duration:?}. Inodes tracked: {}",
            self.inode_map.borrow().len()
        );

        Ok(())
    }

    fn scan_inner(&self, path: &Path) -> anyhow::Result<()> {
        self.metrics.scan_inc(ScanLabels::ElementsScanned);

        let Some(glob_str) = path.to_str() else {
            bail!("invalid path {}", path.display());
        };

        for entry in glob::glob(glob_str)? {
            let path = match entry {
                Ok(p) => p,
                Err(e) => {
                    debug!("Glob expansion failed: {e:?}");
                    self.metrics.scan_inc(ScanLabels::GlobFailed);
                    continue;
                }
            };
            let metadata = match path.metadata() {
                Ok(p) => p,
                Err(e) => {
                    debug!("Failed to get metadata for {}: {e:?}", path.display());
                    self.metrics.scan_inc(ScanLabels::FsMetadataFailed);
                    continue;
                }
            };

            if metadata.is_file() {
                self.metrics.scan_inc(ScanLabels::FileScanned);
                self.update_entry(path.as_path(), &metadata)
                    .with_context(|| format!("Failed to update entry for {}", path.display()))?;
            } else if metadata.is_dir() {
                self.metrics.scan_inc(ScanLabels::DirectoryScanned);
                self.update_entry(path.as_path(), &metadata)
                    .with_context(|| format!("Failed to update entry for {}", path.display()))?;
            } else {
                self.metrics.scan_inc(ScanLabels::FsItemIgnored);
            }
        }
        Ok(())
    }

    fn update_entry(&self, path: &Path, metadata: &Metadata) -> anyhow::Result<()> {
        let inode = inode_key_t {
            inode: metadata.st_ino(),
            dev: metadata.st_dev(),
        };

        let host_path = host_info::remove_host_mount(path);
        self.update_entry_with_inode(inode, host_path)?;

        debug!("Added entry for {}: {inode:?}", path.display());
        Ok(())
    }

    /// Similar to update_entry except we are are directly using the inode instead of the path.
    fn update_entry_with_inode(&self, inode: inode_key_t, path: PathBuf) -> anyhow::Result<()> {
        let mut inode_map = self.inode_map.borrow_mut();
        match inode_map.get_mut(&inode) {
            Some(paths) => {
                // inode is already tracked.
                if !paths.contains(&path) {
                    self.metrics.scan_inc(ScanLabels::FileUpdated);
                    paths.insert(path);
                }
                return Ok(());
            }
            None => {
                self.metrics.scan_inc(ScanLabels::FileUpdated);
                inode_map.insert(inode, HashSet::from([path.clone()]));
            }
        };

        match self.kernel_inode_map.borrow_mut().insert(inode, 0, 0) {
            Ok(_) => Ok(()),
            Err(MapError::SyscallError(SyscallError { io_error, .. }))
                if io_error.kind() == io::ErrorKind::ArgumentListTooLong =>
            {
                bail!(
                    r#"Reached maximum number of inodes to track.
You can increase this limit with:
* The bpf.inodes_max configuration value.
* The FACT_INODES_MAX environment variable.
* The --inodes-max argument."#,
                )
            }
            e => e.with_context(|| format!("Failed to insert kernel entry for {}", path.display())),
        }
    }

    fn get_host_path(&self, inode: Option<&inode_key_t>) -> Option<PathBuf> {
        // The path here needs to be cloned because we won't keep the
        // inode_map borrow long enough.
        // For hardlinks, return any one of the monitored paths
        // TODO: Consider returning the path that matches the event filename
        self.inode_map
            .borrow()
            .get(inode?)
            .and_then(|paths| paths.iter().next().cloned())
    }

    /// Get the specific host path that matches the given filename, if it exists
    /// Otherwise return any monitored path for this inode
    fn get_matching_host_path(
        &self,
        inode: Option<&inode_key_t>,
        filename: &Path,
    ) -> Option<PathBuf> {
        let inode_map = self.inode_map.borrow();
        let paths = inode_map.get(inode?)?;

        // First try to find an exact match
        if paths.contains(filename) {
            return Some(filename.to_path_buf());
        }

        // Otherwise return any monitored path
        paths.iter().next().cloned()
    }

    /// Handle file creation events by adding new inodes to the map.
    ///
    /// We use the parent inode provided by the eBPF code
    /// to look up the parent directory's host path, then construct the full
    /// path by appending the new file's name.
    ///
    /// For hardlinks, the inode already exists but we need to add the new path.
    fn handle_creation_event(&self, event: &Event) -> anyhow::Result<()> {
        let inode = event.get_inode();
        let parent_inode = event.get_parent_inode();

        // For hardlinks, inode is already tracked but we need to add this new path
        // Check if this specific path already exists in our tracking
        let filename = event.get_filename();
        let already_has_this_path = self
            .inode_map
            .borrow()
            .get(inode)
            .is_some_and(|paths| paths.contains(filename));

        if already_has_this_path {
            return Ok(());
        }

        if parent_inode.empty() {
            return Ok(());
        }

        if let Some(filename_component) = filename.file_name()
            && let Some(parent_host_path) = self.get_host_path(Some(parent_inode))
        {
            let host_path = parent_host_path.join(filename_component);
            self.update_entry_with_inode(*inode, host_path)
                .with_context(|| {
                    format!(
                        "Failed to add creation event entry for {}",
                        filename_component.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Handle unlink events by removing the specific path from the inode->paths map.
    ///
    /// With hardlinks, we only remove the specific path being unlinked.
    /// The kernel already removed from kernel inode map if nlink reached 0.
    fn handle_unlink_event(&self, event: &Event) {
        let inode = event.get_inode();
        let filename = event.get_filename();
        let mut inode_map = self.inode_map.borrow_mut();

        if let Some(paths) = inode_map.get_mut(inode) {
            // Remove the specific path being unlinked
            paths.remove(filename);

            // If no monitored paths remain for this inode, remove the inode entry
            // The kernel already removed it from kernel map if nlink==0
            if paths.is_empty() {
                inode_map.remove(inode);
                self.metrics.scan_inc(ScanLabels::InodeRemoved);
            }
        }

        self.metrics.scan_inc(ScanLabels::FileRemoved);
    }

    fn handle_rename_event(&self, event: &mut Event) {
        let old_filename = event.get_old_filename().cloned();
        let new_filename = event.get_filename().clone();

        match event.get_monitored() {
            monitored_t::MONITORED_BY_INODE => {
                // Renaming onto an existing tracked file.
                // The target inode (being overwritten) was already removed from kernel map if needed.
                // For the moving inode, update its path in our tracking.
                let mut inode_map = self.inode_map.borrow_mut();

                let Some(old_inode) = event.get_old_inode() else {
                    unreachable!("old inode not found for rename event");
                };

                // Remove the old path and add the new path for the moving inode
                if let Some(paths) = inode_map.get_mut(old_inode) {
                    if let Some(ref old_fname) = old_filename {
                        paths.remove(old_fname);
                    }
                    paths.insert(new_filename);
                }
            }
            monitored_t::NOT_MONITORED
                if event.get_old_monitored() == Some(monitored_t::MONITORED_BY_INODE) =>
            {
                // Renaming from a monitored path to an unmonitored path
                let Some(old_inode) = event.get_old_inode() else {
                    return;
                };
                let Some(ref old_fname) = old_filename else {
                    return;
                };

                let mut inode_map = self.inode_map.borrow_mut();

                if let Some(paths) = inode_map.get_mut(old_inode) {
                    // Remove this specific path from tracking
                    paths.remove(old_fname);

                    // If no monitored paths remain, remove the inode
                    // Note: kernel may have already removed it if nlink==0
                    if paths.is_empty() {
                        inode_map.remove(old_inode);
                        // Don't call kernel remove here - kernel handles it based on nlink
                    }
                }
            }
            monitored_t::NOT_MONITORED => {
                // The new path is not monitored and the old path is most likely
                // matching by path, we don't need to do anything in this case.
            }
            monitored_t::MONITORED_BY_PARENT if !event.get_inode().empty() => {
                // The parent for the target is monitored, but the file itself
                // is not. This is renaming onto an existing file that will be overwritten.
                // The overwritten inode was already handled by kernel.

                // For the moving file, update its path
                let Some(old_inode) = event.get_old_inode() else {
                    return;
                };

                let mut inode_map = self.inode_map.borrow_mut();
                if let Some(paths) = inode_map.get_mut(old_inode) {
                    if let Some(ref old_fname) = old_filename {
                        paths.remove(old_fname);
                    }

                    // Check if new path should be tracked
                    if self.paths_globset.is_match(&new_filename) {
                        paths.insert(new_filename.clone());
                        event.set_host_path(new_filename);
                    } else if paths.is_empty() {
                        // No monitored paths left
                        inode_map.remove(old_inode);
                    }
                }
            }
            monitored_t::MONITORED_BY_PARENT
                if event.get_old_monitored() == Some(monitored_t::MONITORED_BY_INODE) =>
            {
                // Renaming into a monitored directory
                let mut inode_map = self.inode_map.borrow_mut();

                // Get the parent path to construct the new full path
                let Some(parent_paths) = inode_map.get(event.get_parent_inode()) else {
                    warn!("Failed to get parent host path");
                    return;
                };
                let Some(parent_path) = parent_paths.iter().next() else {
                    return;
                };

                let Some(filename_component) = new_filename.file_name() else {
                    warn!("Failed to get last component from event");
                    return;
                };
                let new_host_path = parent_path.join(filename_component);

                if self.paths_globset.is_match(&new_host_path) {
                    // New path needs to be tracked.
                    // Update the moving inode's paths to point to the new location
                    let moving_inode = event.get_inode();
                    if let Some(paths) = inode_map.get_mut(moving_inode) {
                        if let Some(ref old_fname) = old_filename {
                            paths.remove(old_fname);
                        }
                        paths.insert(new_host_path.clone());
                    }

                    // Add the new host path to the event
                    event.set_host_path(new_host_path);
                } else {
                    // New path not tracked, remove old path
                    let moving_inode = event.get_inode();
                    if let Some(paths) = inode_map.get_mut(moving_inode) {
                        if let Some(ref old_fname) = old_filename {
                            paths.remove(old_fname);
                        }
                        if paths.is_empty() {
                            inode_map.remove(moving_inode);
                        }
                    }
                }
            }
            monitored_t::MONITORED_BY_PARENT => {
                // Target location might be monitored, but we don't have path info
                // Scan to fix the inode maps
                if let Err(e) = self.scan() {
                    warn!("Scan failed: {e:?}");
                }

                // Try to get a path for the old inode
                if let Some(old_inode) = event.get_old_inode()
                    && let Some(path) = self.get_host_path(Some(old_inode))
                {
                    event.set_host_path(path);
                }
            }
            monitored_t::MONITORED_BY_PATH => {
                // Nothing to do here, no inode tracking involved
            }
            _ => unreachable!("Invalid monitored value"),
        }
    }

    /// Handle a mount being modified in a monitored directory.
    ///
    /// This should really do a partial scan of the directory where the
    /// mount is being changed, but we don't have an easy way to do that
    /// at the moment, so we trigger a full scan instead.
    fn handle_mount_event(&self) {
        if let Err(e) = self.scan() {
            warn!("Host scan failed: {e:?}");
        }
    }

    /// Periodically notify the host scanner main task that a scan needs
    /// to happen.
    ///
    /// This is needed because `tokio::time::Interval::tick` will create
    /// a new future every time it is called, if used in a
    /// `tokio::select` with other events that trigger more often, the
    /// tick will never happen. This way we have a separate task that
    /// will reliably send a notification to the main one.
    fn start_scan_notifier(&self, scan_trigger: Arc<Notify>, mut running: watch::Receiver<bool>) {
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

    pub fn start(mut self, task_set: &mut JoinSet<anyhow::Result<()>>) {
        let scan_interval_value = *self.scan_interval.borrow();
        let scan_trigger = Arc::new(Notify::new());
        let (running, running_rx) = watch::channel(true);

        if scan_interval_value.is_zero() {
            warn!("Host scanner periodic scans permanently disabled (scan_interval is 0)");
        } else {
            self.start_scan_notifier(scan_trigger.clone(), running_rx);
        }

        task_set.spawn(async move {
            info!("Starting host scanner...");

            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(mut event) = event else {
                            info!("No more events to process");
                            break;
                        };
                        self.metrics.events.added();

                        // Handle file and directory creation events by adding new inodes to the map
                        if event.is_creation() &&
                            let Err(e) = self.handle_creation_event(&event) {
                                warn!("Failed to handle creation event: {e}");
                            }

                        // Handle mount events and move on.
                        if event.is_mount_related() {
                            self.handle_mount_event();
                            continue;
                        }

                        // Handle mount events and move on.
                        if event.is_mount_related() {
                            self.handle_mount_event();
                            continue;
                        }

                        // For hardlinks, try to match the exact path from the event
                        if let Some(host_path) = self.get_matching_host_path(Some(event.get_inode()), event.get_filename()) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_host_path(host_path);
                        }

                        if let Some(old_filename) = event.get_old_filename() && let Some(host_path) = self.get_matching_host_path(event.get_old_inode(), old_filename) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_old_host_path(host_path);
                        }

                        // Remove inode from the map
                        if event.is_deletion() {
                            self.handle_unlink_event(&event);
                        }

                        // Skip directory creation and deletion events - we track them internally but don't send to sensor
                        if event.is_mkdir() || event.is_rmdir() {
                            continue;
                        }

                        if event.is_rename() { self.handle_rename_event(&mut event); }

                        if event.is_monitored_by_parent() &&
                            !self.paths_globset.is_match(event.get_host_path()) {
                            // The event was monitored by parent, but the host
                            // path is not to be monitored, so we ignore the
                            // event and attempt to remove the inode from the
                            // maps to prevent it from sending more events.
                             let mut inode_map = self.inode_map.borrow_mut();
                             if let Some(paths) = inode_map.get_mut(event.get_inode()) {
                                 paths.remove(event.get_filename());
                                 if paths.is_empty() {
                                     inode_map.remove(event.get_inode());
                                     // Kernel handles removal based on nlink
                                 }
                             }
                            self.metrics.events.ignored();
                            continue;
                        }

                        if let Err(e) = self.tx.send(event).await {
                            self.metrics.events.dropped();
                            warn!("Failed to send event: {e}");
                        }
                    },
                    req = self.introspection.recv() => {
                        let Some(req) = req else {
                            continue;
                        };

                        let resp = serde_json::to_string(&*self.inode_map.borrow());
                        if let Err(e) = req.send(resp) {
                            warn!("Failed to reply introspection query: {e:?}");
                        }
                    }
                    _ = scan_trigger.notified() => self.scan()?,
                    _ = self.paths.changed() => {
                            self.paths_globset = HostScanner::build_globset(self.paths.borrow().as_slice())?;
                            self.scan()?;
                        }
                }
            }

            let _ = running.send(false);

            info!("Stopping host scanner");
            Ok(())
        });
    }
}
