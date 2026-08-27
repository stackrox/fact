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
    collections::{HashMap, HashSet},
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
    host_info::{self, remove_host_mount},
    metrics::host_scanner::{HostScannerLabels, HostScannerMetrics, ScanLabels},
};

struct InodeMap(HashMap<inode_key_t, PathBuf>);

impl InodeMap {
    fn new() -> Self {
        InodeMap(HashMap::new())
    }
}

impl Deref for InodeMap {
    type Target = HashMap<inode_key_t, PathBuf>;

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

#[derive(Debug)]
pub enum IntrospectionRequestType {
    InodeMap,
    InodeMapSize,
}

#[derive(Debug)]
pub enum IntrospectionResponseType {
    InodeMap(serde_json::Result<String>),
    InodeMapSize,
}

pub type IntrospectionRequest = (
    IntrospectionRequestType,
    oneshot::Sender<IntrospectionResponseType>,
);

pub struct HostScanner {
    kernel_inode_map: RefCell<aya::maps::HashMap<MapData, inode_key_t, inode_value_t>>,
    inode_map: RefCell<InodeMap>,

    paths: watch::Receiver<Vec<PathBuf>>,
    scan_interval: watch::Receiver<Duration>,

    rx: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    introspection: mpsc::Receiver<IntrospectionRequest>,

    metrics: HostScannerMetrics,

    paths_globset: GlobSet,
    paths_patterns: Vec<PathBuf>,
}

impl HostScanner {
    pub fn new(
        bpf: &mut Bpf,
        rx: mpsc::Receiver<Event>,
        paths: watch::Receiver<Vec<PathBuf>>,
        scan_interval: watch::Receiver<Duration>,
        metrics: HostScannerMetrics,
        introspection: mpsc::Receiver<IntrospectionRequest>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Event>)> {
        let kernel_inode_map = RefCell::new(bpf.take_inode_map()?);
        let inode_map = RefCell::new(InodeMap::new());
        let (tx, output) = mpsc::channel(100);

        let mut host_scanner = HostScanner {
            kernel_inode_map,
            inode_map,
            paths,
            scan_interval,
            rx,
            tx,
            introspection,
            metrics,
            paths_globset: GlobSet::empty(),
            paths_patterns: Vec::new(),
        };

        host_scanner.reload_paths_config()?;

        // Run an initial scan to fill in the inode map
        host_scanner.scan()?;

        Ok((host_scanner, output))
    }

    fn reload_paths_config(&mut self) -> anyhow::Result<()> {
        let paths = self.paths.borrow();
        let mut builder = GlobSetBuilder::new();
        let mut patterns = Vec::with_capacity(paths.len());

        for p in paths.iter() {
            patterns.push(host_info::prepend_host_mount(p));

            let Some(glob_str) = p.to_str() else {
                bail!("failed to convert path {} to string", p.display());
            };

            builder.add(Glob::new(glob_str).with_context(|| format!("invalid glob {}", glob_str))?);
        }

        self.paths_globset = builder.build()?;
        self.paths_patterns = patterns;

        Ok(())
    }

    fn scan(&self) -> anyhow::Result<()> {
        info!("Host scan started");
        let start = Instant::now();
        self.metrics.scan_inc(ScanLabels::Scans);

        // Cleanup any items that are either:
        // * Not configured to be monitored anymore.
        // * Are configured to be monitored but no longer are found in
        //   the file system.
        self.inode_map.borrow_mut().retain(|inode, path| {
            if self.paths_globset.is_match(&path) && host_info::prepend_host_mount(path).exists() {
                true
            } else {
                let _ = self.kernel_inode_map.borrow_mut().remove(inode);
                self.metrics.scan_inc(ScanLabels::InodeRemoved);
                false
            }
        });

        for path in &self.paths_patterns {
            self.scan_inner(path)?;
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
            let metadata = match path.symlink_metadata() {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    warn!("Failed to get metadata for {}: {e}", path.display());
                    continue;
                }
            };

            if metadata.is_file() {
                self.metrics.scan_inc(ScanLabels::FileScanned);
            } else if metadata.is_symlink() {
                self.metrics.scan_inc(ScanLabels::SymlinkScanned);
                self.scan_symlink(&path);
            } else if metadata.is_dir() {
                self.metrics.scan_inc(ScanLabels::DirectoryScanned);
            } else {
                self.metrics.scan_inc(ScanLabels::FsItemIgnored);
                continue;
            }

            self.update_entry(&path, &metadata)
                .with_context(|| format!("Failed to update entry for {}", path.display()))?;
        }
        Ok(())
    }

    fn scan_symlink(&self, path: &Path) {
        let target = match path.read_link() {
            Ok(p) => {
                if p.has_root() {
                    &host_info::prepend_host_mount(&p)
                } else {
                    path
                }
            }
            Err(e) => {
                warn!("Failed to read symlink path: {e}");
                return;
            }
        };

        match target.metadata() {
            Ok(metadata) => {
                if let Err(e) = self.update_entry(path, &metadata) {
                    warn!("Failed to update symlink entry for {}: {e}", path.display());
                }
            }
            Err(e) => {
                warn!(
                    "Failed to read metadata for symlink target {}: {e}",
                    target.display()
                );
            }
        }
    }

    /// Do a partial scan of any pattern that matches the provided path
    ///
    /// This includes glob expansion matching and any patterns with a
    /// base path (the path up to the first glob special character) that
    /// matches the supplied path.
    fn scan_partial(&self, path: &Path) -> anyhow::Result<()> {
        let start = Instant::now();
        let scan_prefix_patterns =
            self.paths_patterns
                .iter()
                .enumerate()
                .filter_map(|(i, pattern)| {
                    remove_host_mount(pattern)
                        .to_str()?
                        .split(['*', '?', '[', '{'])
                        .next()?
                        .starts_with(path.to_str()?)
                        .then_some(i)
                });
        let scan_glob_index = self.paths_globset.matches(path);

        // De-duplicate the indexes
        let scan_set = scan_prefix_patterns
            .chain(scan_glob_index.iter().copied())
            .collect::<HashSet<_>>();

        for pattern in scan_set.iter().map(|index| &self.paths_patterns[*index]) {
            self.scan_inner(pattern)?;
        }

        self.metrics
            .scan_partial_duration
            .observe(start.elapsed().as_secs_f64());
        Ok(())
    }

    fn update_entry(&self, path: &Path, metadata: &Metadata) -> anyhow::Result<()> {
        let inode = inode_key_t {
            inode: metadata.st_ino(),
            dev: metadata.st_dev(),
        };

        let host_path = host_info::remove_host_mount(path);
        self.update_entry_with_inode(inode, host_path.to_path_buf())?;

        debug!("Added entry for {}: {inode:?}", path.display());
        Ok(())
    }

    /// Similar to update_entry except we are are directly using the inode instead of the path.
    fn update_entry_with_inode(&self, inode: inode_key_t, path: PathBuf) -> anyhow::Result<()> {
        let mut inode_map = self.inode_map.borrow_mut();
        match inode_map.get_mut(&inode) {
            Some(p) => {
                // inode is already tracked.
                if path != *p {
                    *p = path;
                    self.metrics.scan_inc(ScanLabels::FileUpdated);
                }
                return Ok(());
            }
            None => {
                self.metrics.scan_inc(ScanLabels::FileUpdated);
                inode_map.insert(inode, path.clone());
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
        self.inode_map.borrow().get(inode?).cloned()
    }

    fn build_host_path(&self, event: &Event) -> Option<PathBuf> {
        let parent_inode = event.get_parent_inode();

        if !parent_inode.empty()
            && let Some(filename) = event.get_filename().file_name()
            && let Some(parent_host_path) = self.get_host_path(Some(parent_inode))
        {
            Some(parent_host_path.join(filename))
        } else {
            None
        }
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

        match self.build_host_path(event) {
            Some(host_path) => self
                .update_entry_with_inode(*inode, host_path)
                .with_context(|| {
                    format!(
                        "Failed to add creation event entry for {}",
                        event.get_filename().display(),
                    )
                }),

            None => Ok(()),
        }
    }

    /// Handle unlink events by removing the inode from the inode->path map.
    ///
    /// The probe already cleared the kernel inode map.
    fn handle_unlink_event(&self, event: &Event) {
        let inode = event.get_inode();

        if self.inode_map.borrow_mut().remove(inode).is_some() {
            self.metrics.scan_inc(ScanLabels::InodeRemoved);
        }

        self.metrics.scan_inc(ScanLabels::FileRemoved);
    }

    fn handle_rename_event(&self, event: &mut Event) {
        match event.get_monitored() {
            monitored_t::MONITORED_BY_INODE => {
                // This condition means a file is being renamed and taking the
                // place of an existing, tracked file. We need to remove the
                // inode we are landing on and put the associated host path in
                // the old inode.
                let mut inode_map = self.inode_map.borrow_mut();
                let Some(path) = inode_map.remove(event.get_inode()) else {
                    warn!("Old path was not found for inode tracked event");
                    return;
                };
                let Some(old_inode) = event.get_old_inode() else {
                    unreachable!("old inode not found for rename event");
                };
                inode_map.insert(*old_inode, path);
            }
            monitored_t::NOT_MONITORED
                if event.get_old_monitored() == Some(monitored_t::MONITORED_BY_INODE) =>
            {
                // We are landing on a path that is not tracked at all, remove
                // the entries for the old path from the map
                let Some(old_host_path) = event.get_old_host_path() else {
                    warn!("Rename event did not have old host path for inode tracked item");
                    return;
                };
                self.inode_map.borrow_mut().retain(|inode, path| {
                    if !path.starts_with(old_host_path) {
                        return true;
                    }

                    let _ = self.kernel_inode_map.borrow_mut().remove(inode);
                    false
                });
            }
            monitored_t::NOT_MONITORED => {
                // The new path is not monitored and the old path is most likely
                // matching by path, we don't need to do anything in this case.
            }
            monitored_t::MONITORED_BY_PARENT if !event.get_inode().empty() => {
                // The parent for the target is monitored, but the file itself
                // is not. Remove the entry for the old file from the map.
                self.inode_map.borrow_mut().remove(
                    event
                        .get_old_inode()
                        .expect("rename event did not have old inode"),
                );
            }
            monitored_t::MONITORED_BY_PARENT
                if event.get_old_monitored() == Some(monitored_t::MONITORED_BY_INODE) =>
            {
                // The target is monitored by parent and we are landing on a
                // path that didn't hold anything, we need to figure out the
                // host path and check if we should track it.
                let mut inode_map = self.inode_map.borrow_mut();
                let Some(new_host_parent) = inode_map.get(event.get_parent_inode()) else {
                    warn!("Failed to get parent host path");
                    return;
                };
                let Some(filename) = event.get_filename().file_name() else {
                    warn!("Failed to get last component from event: {event:#?}");
                    return;
                };
                let new_host_path = new_host_parent.join(filename);
                let Some(old_host_path) = event.get_old_host_path() else {
                    unreachable!("Rename event did not have an old host path");
                };

                if self.paths_globset.is_match(&new_host_path) {
                    // New path needs to be tracked.
                    // Move all entries for the old host path to the new one
                    for path in inode_map.values_mut() {
                        if let Ok(suffix) = path.strip_prefix(old_host_path) {
                            if suffix == Path::new("") {
                                *path = new_host_path.clone();
                            } else {
                                *path = new_host_path.join(suffix);
                            }
                        }
                    }

                    // Add the new host path to the event
                    event.set_host_path(new_host_path);
                } else {
                    // New path is not tracked, remove old entries
                    inode_map.retain(|inode, path| {
                        if !path.starts_with(old_host_path) {
                            return true;
                        }
                        if let Err(e) = self.kernel_inode_map.borrow_mut().remove(inode) {
                            warn!("Failed to remove inode kernel entry: {e:?}");
                        }
                        false
                    });
                }
            }
            monitored_t::MONITORED_BY_PARENT => {
                // In this case, the target location might be monitored, but we
                // don't have any information of the host path for the old path,
                // best we can do is attempt to scan the file system and fix the
                // inode maps that way.
                if let Err(e) = self.scan() {
                    warn!("Scan failed: {e:?}");
                }

                // Attempt to update the host path with the old inode
                if let Some(old_inode) = event.get_old_inode()
                    && let Some(path) = self.inode_map.borrow().get(old_inode)
                {
                    event.set_host_path(path.clone());
                }
            }
            monitored_t::MONITORED_BY_PATH => {
                // Nothing to do here, having one side of the rename monitored
                // by path means at best the other side is also monitored by
                // path, no inode tracking is involved.
            }
            _ => unreachable!("Invalid monitored value"),
        }
    }

    /// Handle a mount being modified in a monitored directory.
    fn handle_mount_event(&self, event: &Event) {
        if let Err(e) = self.scan_partial(event.get_host_path()) {
            warn!("Host scan failed: {e:?}");
        }
    }

    /// Handle symlink events by scanning the filesystem
    fn handle_symlink_event(&self, event: &Event) -> anyhow::Result<()> {
        // Since `glob` follows symlinks unconditionally, we need to do
        // so as well.
        self.scan_partial(event.get_host_path())
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

    /// Check whether an event should be ignored.
    ///
    /// On top of the check from `Event::is_ignored`, this also checks
    /// the host paths for matches in events that are monitored by
    /// parent.
    fn event_is_ignored(&self, event: &Event) -> bool {
        event.is_ignored(&self.paths_globset)
            && !self.paths_globset.is_match(event.get_host_path())
            && event
                .get_old_host_path()
                .is_none_or(|path| !self.paths_globset.is_match(path))
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
                        self.metrics.events_inc(HostScannerLabels::Total);

                        // Handle file and directory creation events by adding new inodes to the map
                        if event.is_creation() &&
                            let Err(e) = self.handle_creation_event(&event) {
                                warn!("Failed to handle creation event: {e}");
                            }

                        if let Some(host_path) = self.get_host_path(Some(event.get_inode())) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_host_path(host_path);
                        }

                        if let Some(host_path) = self.get_host_path(event.get_old_inode()) {
                            self.metrics.scan_inc(ScanLabels::InodeHit);
                            event.set_old_host_path(host_path);
                        }

                        // Handle mount events and move on.
                        if event.is_mount_related() {
                            self.metrics.events_inc(HostScannerLabels::Mount);
                            self.handle_mount_event(&event);
                            continue;
                        }

                        // Remove inode from the map
                        if event.is_deletion() {
                            self.handle_unlink_event(&event);
                        }

                        // Skip directory creation and deletion events - we track them internally but don't send to sensor
                        if event.is_mkdir() {
                            self.metrics.events_inc(HostScannerLabels::MkDir);
                            continue;
                        } else if event.is_rmdir() {
                            self.metrics.events_inc(HostScannerLabels::RmDir);
                            continue;
                        }

                        if event.is_symlink() &&
                            let Err(e) = self.handle_symlink_event(&event) {
                                warn!("Failed to handle symlink event: {e:?}");
                            }

                        if event.is_rename() { self.handle_rename_event(&mut event); }

                        // Before sending the event forward, we need to check
                        // whether the event is ignored now that we have the
                        // full inode context.
                        if self.event_is_ignored(&event) {
                            self.inode_map.borrow_mut().remove(event.get_inode());
                            let _ = self.kernel_inode_map.borrow_mut().remove(event.get_inode());
                            if let Some(old_inode) = event.get_old_inode() {
                                self.inode_map.borrow_mut().remove(old_inode);
                                let _ = self.kernel_inode_map.borrow_mut().remove(old_inode);
                            }
                            self.metrics.events_inc(HostScannerLabels::Ignored);
                            continue;
                        }

                        if let Err(e) = self.tx.send(event).await {
                            self.metrics.events_inc(HostScannerLabels::Dropped);
                            warn!("Failed to send event: {e}");
                        } else {
                            self.metrics.events_inc(HostScannerLabels::Added);
                        }
                    },
                    req = self.introspection.recv() => {
                        let Some((req_type, ch)) = req else {
                            continue;
                        };

                        use IntrospectionRequestType::*;
                        let resp = match req_type {
                            InodeMap => {
                                let resp = serde_json::to_string(&*self.inode_map.borrow());
                                IntrospectionResponseType::InodeMap(resp)
                            }
                            InodeMapSize => {
                                let len = self.inode_map.borrow().len();
                                self.metrics.inode_map_size.set(len as i64);
                                IntrospectionResponseType::InodeMapSize
                            }
                        };
                        if let Err(e) = ch.send(resp) {
                            warn!("Failed to reply introspection query: {e:?}");
                        }
                    }
                    _ = scan_trigger.notified() => self.scan()?,
                    _ = self.paths.changed() => {
                            self.reload_paths_config()?;
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
