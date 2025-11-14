use std::{
    collections::HashMap, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc, time::Duration,
};

use log::{debug, info, warn};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::interval,
};

use super::{builder::FactConfigBuilder, EndpointConfig, FactConfig, GrpcConfig};

const CONFIG_FILES: [&str; 4] = [
    "/etc/stackrox/fact.yml",
    "/etc/stackrox/fact.yaml",
    "fact.yml",
    "fact.yaml",
];

pub struct Reloader {
    config: FactConfig,
    builder: FactConfigBuilder,
    endpoint: watch::Sender<EndpointConfig>,
    grpc: watch::Sender<GrpcConfig>,
    paths: watch::Sender<Vec<PathBuf>>,
    files: HashMap<PathBuf, i64>,
    trigger: Arc<Notify>,
}

impl Reloader {
    pub fn new() -> anyhow::Result<Self> {
        let builder = FactConfigBuilder::new().add_files(CONFIG_FILES.as_slice());
        let config = builder.build()?;
        info!("Startup configuration: {config:#?}");

        let (endpoint, _) = watch::channel(config.endpoint.clone());
        let (grpc, _) = watch::channel(config.grpc.clone());
        let (paths, _) = watch::channel(config.paths().to_vec());
        let trigger = Arc::new(Notify::new());
        let files = builder
            .files()
            .iter()
            .filter_map(|path| {
                if path.exists() {
                    let mtime = match path.metadata() {
                        Ok(m) => m.mtime(),
                        Err(e) => {
                            warn!("Failed to stat {}: {e}", path.display());
                            warn!("Configuration reloading may not work");
                            return None;
                        }
                    };
                    Some((path.clone(), mtime))
                } else {
                    None
                }
            })
            .collect();

        Ok(Reloader {
            config,
            builder,
            endpoint,
            grpc,
            paths,
            files,
            trigger,
        })
    }

    /// Consume the reloader into a task
    ///
    /// The resulting task will handle reloading the configuration and
    /// forwarding the changes to any parts of the program that might
    /// need to take action accordingly.
    ///
    /// If hotreload is disabled on startup the task will not be
    /// spawned.
    pub fn start(mut self, mut running: watch::Receiver<bool>) -> Option<JoinHandle<()>> {
        if !self.config.hotreload() {
            info!("Configuration hotreload is disabled, changes will require a restart.");
            return None;
        }

        let handle = tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = ticker.tick() => self.reload(),
                    _ = self.trigger.notified() => self.reload(),
                    _ = running.changed() => {
                        if !*running.borrow() {
                            info!("Stopping config reloader...");
                            return;
                        }
                    }
                }
            }
        });
        Some(handle)
    }

    pub fn config(&self) -> &FactConfig {
        &self.config
    }

    /// Subscribe to get notifications when endpoint configuration is
    /// changed.
    pub fn endpoint(&self) -> watch::Receiver<EndpointConfig> {
        self.endpoint.subscribe()
    }

    /// Subscribe to get notifications when grpc configuration is
    /// changed.
    pub fn grpc(&self) -> watch::Receiver<GrpcConfig> {
        self.grpc.subscribe()
    }

    /// Subscribe to get notifications when paths configuration is
    /// changed.
    pub fn paths(&self) -> watch::Receiver<Vec<PathBuf>> {
        self.paths.subscribe()
    }

    /// Get a reference to the internal trigger for manual reloading of
    /// configuration.
    ///
    /// Mainly meant as a way to handle the SIGHUP signal, but could be
    /// extended to other use cases.
    pub fn get_trigger(&self) -> Arc<Notify> {
        self.trigger.clone()
    }

    /// Go through the configuration files and reload the modification
    /// time for each of them.
    ///
    /// Returns true if any file has been modified.
    fn update_cache(&mut self) -> bool {
        let mut res = false;

        for file in self.builder.files() {
            if file.exists() {
                let mtime = match file.metadata() {
                    Ok(m) => m.mtime(),
                    Err(e) => {
                        warn!("Failed to stat {}: {e}", file.display());
                        warn!("Configuration reloading may not work");
                        continue;
                    }
                };
                match self.files.get_mut(file) {
                    Some(old) if *old == mtime => {}
                    Some(old) => {
                        debug!("Updating '{}'", file.display());
                        res = true;
                        *old = mtime;
                    }
                    None => {
                        debug!("New configuration file '{}'", file.display());
                        res = true;
                        self.files.insert(file.clone(), mtime);
                    }
                }
            } else if self.files.contains_key(file) {
                debug!("'{}' no longer exists, removing from cache", file.display());
                res = true;
                self.files.remove(file);
            }
        }
        res
    }

    /// Recreate the configuration and notify of changes to any
    /// subscribers.
    fn reload(&mut self) {
        if !self.update_cache() {
            return;
        }

        let new = match self.builder.build() {
            Ok(config) => config,
            Err(e) => {
                warn!("Configuration reloading failed: {e}");
                return;
            }
        };
        info!("Updated configuration: {new:#?}");

        self.endpoint.send_if_modified(|old| {
            if *old != new.endpoint {
                debug!("Sending new endpoint configuration...");
                *old = new.endpoint.clone();
                true
            } else {
                false
            }
        });

        self.grpc.send_if_modified(|old| {
            if *old != new.grpc {
                debug!("Sending new gRPC configuration...");
                *old = new.grpc.clone();
                true
            } else {
                false
            }
        });

        self.paths.send_if_modified(|old| {
            let new = new.paths();
            if *old != new {
                debug!("Sending new paths configuration...");
                *old = new.to_vec();
                true
            } else {
                false
            }
        });

        if self.config.hotreload() != new.hotreload() {
            warn!("Changes to the hotreload field only take effect on startup");
        }

        self.config = new;
    }
}
