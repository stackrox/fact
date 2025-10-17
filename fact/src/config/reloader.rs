use std::{
    collections::HashMap, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc, time::Duration,
};

use log::{debug, info, warn};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::interval,
};

use super::{EndpointConfig, FactConfig, CONFIG_PATHS};

pub struct Reloader {
    config: FactConfig,
    endpoint: watch::Sender<EndpointConfig>,
    files: HashMap<&'static str, i64>,
    trigger: Arc<Notify>,
}

impl Reloader {
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

    /// Subscribe to get notifications when endpoint configuration is
    /// changed.
    pub fn endpoint(&self) -> watch::Receiver<EndpointConfig> {
        self.endpoint.subscribe()
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

        for path in CONFIG_PATHS {
            let p = PathBuf::from(path);
            if p.exists() {
                let mtime = match p.metadata() {
                    Ok(m) => m.mtime(),
                    Err(e) => {
                        warn!("Failed to stat {path}: {e}");
                        warn!("Configuration reloading may not work");
                        continue;
                    }
                };
                match self.files.get_mut(&path) {
                    Some(old) if *old == mtime => {}
                    Some(old) => {
                        res = true;
                        *old = mtime;
                    }
                    None => {
                        res = true;
                        self.files.insert(path, mtime);
                    }
                }
            } else if self.files.contains_key(&path) {
                res = true;
                self.files.remove(&path);
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

        let new = match FactConfig::build() {
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

        if self.config.hotreload() != new.hotreload() {
            warn!("Changes to the hotreload field only take effect on startup");
        }

        self.config = new;
    }
}

impl From<FactConfig> for Reloader {
    fn from(config: FactConfig) -> Self {
        let files = CONFIG_PATHS
            .iter()
            .filter_map(|path| {
                let p = PathBuf::from(path);
                if p.exists() {
                    let mtime = match p.metadata() {
                        Ok(m) => m.mtime(),
                        Err(e) => {
                            warn!("Failed to stat {path}: {e}");
                            warn!("Configuration reloading may not work");
                            return None;
                        }
                    };
                    Some((*path, mtime))
                } else {
                    None
                }
            })
            .collect();
        let (endpoint, _) = watch::channel(config.endpoint.clone());
        let trigger = Arc::new(Notify::new());
        Reloader {
            config,
            endpoint,
            files,
            trigger,
        }
    }
}
