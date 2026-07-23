use std::{
    collections::HashMap, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc, time::Duration,
};

use log::{debug, info, warn};
use tokio::{
    sync::{Notify, watch},
    time::interval,
};

use crate::config::OTelConfig;

use super::{CONFIG_FILES, EndpointConfig, FactConfig, GrpcConfig};

pub struct Reloader {
    config: FactConfig,
    endpoint: watch::Sender<EndpointConfig>,
    grpc: watch::Sender<GrpcConfig>,
    otel: watch::Sender<OTelConfig>,
    paths: watch::Sender<Vec<PathBuf>>,
    files: HashMap<&'static str, i64>,
    scan_interval: watch::Sender<Duration>,
    rate_limit: watch::Sender<u64>,
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
    pub fn start(mut self, mut running: watch::Receiver<bool>) {
        if !self.config.hotreload() {
            info!("Configuration hotreload is disabled, changes will require a restart.");
            return;
        }

        tokio::spawn(async move {
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

    /// Subscribe to get notifications when otel configuration is
    /// changed.
    pub fn otel(&self) -> watch::Receiver<OTelConfig> {
        self.otel.subscribe()
    }

    /// Subscribe to get notifications when paths configuration is
    /// changed.
    pub fn paths(&self) -> watch::Receiver<Vec<PathBuf>> {
        self.paths.subscribe()
    }

    /// Subscribe to get notifications when scan_interval configuration
    /// is changed.
    pub fn scan_interval(&self) -> watch::Receiver<Duration> {
        self.scan_interval.subscribe()
    }

    /// Subscribe to get notifications when rate_limit configuration
    /// is changed.
    pub fn rate_limit(&self) -> watch::Receiver<u64> {
        self.rate_limit.subscribe()
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

        for file in CONFIG_FILES {
            let path = PathBuf::from(file);
            if path.exists() {
                let mtime = match path.metadata() {
                    Ok(m) => m.mtime(),
                    Err(e) => {
                        warn!("Failed to stat {file}: {e}");
                        warn!("Configuration reloading may not work");
                        continue;
                    }
                };
                match self.files.get_mut(&file) {
                    Some(old) if *old == mtime => {}
                    Some(old) => {
                        debug!("Updating '{file}'");
                        res = true;
                        *old = mtime;
                    }
                    None => {
                        debug!("New configuration file '{file}'");
                        res = true;
                        self.files.insert(file, mtime);
                    }
                }
            } else if self.files.contains_key(&file) {
                debug!("'{file}' no longer exists, removing from cache");
                res = true;
                self.files.remove(&file);
            }
        }
        res
    }

    /// Compare endpoint configurations and figure out if reloading is
    /// needed.
    ///
    /// EndpointConfig has non-reloadable fields, its PartialEq
    /// implementation still has all fields so unit tests can check
    /// properly.
    ///
    /// The first argument is destructured here so the compiler
    /// complains when new fields are added, making sure we fix this
    /// with things that need to be reloaded.
    fn endpoint_should_reload(
        &EndpointConfig {
            address: l_address,
            expose_metrics: l_expose_metrics,
            health_check: l_health_check,
            introspection: _,
        }: &EndpointConfig,
        right: &EndpointConfig,
    ) -> bool {
        l_address != right.address
            || l_expose_metrics != right.expose_metrics
            || l_health_check != right.health_check
    }

    /// Propagate configuration changes to all subscribers that need it
    fn send_updates(&self, new: &FactConfig) {
        self.endpoint.send_if_modified(|old| {
            if Reloader::endpoint_should_reload(old, &new.endpoint) {
                debug!("Sending new endpoint configuration...");
                *old = EndpointConfig {
                    introspection: old.introspection,
                    ..new.endpoint
                };
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

        self.otel.send_if_modified(|old| {
            if *old != new.otel {
                debug!("Sending new OTel configuration...");
                *old = new.otel.clone();
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

        self.scan_interval.send_if_modified(|old| {
            let new = new.scan_interval();
            if *old != new {
                debug!("Sending new scan interval configuration...");
                *old = new;
                true
            } else {
                false
            }
        });

        self.rate_limit.send_if_modified(|old| {
            let new = new.rate_limit();
            if *old != new {
                debug!("Sending new rate limit configuration...");
                *old = new;
                true
            } else {
                false
            }
        });

        if self.config.hotreload() != new.hotreload() {
            warn!("Changes to the hotreload field only take effect on startup");
        }
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

        self.send_updates(&new);

        self.config = new;
    }
}

impl From<FactConfig> for Reloader {
    fn from(config: FactConfig) -> Self {
        let files = CONFIG_FILES
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
        let (grpc, _) = watch::channel(config.grpc.clone());
        let (otel, _) = watch::channel(config.otel.clone());
        let (paths, _) = watch::channel(config.paths().to_vec());
        let (scan_interval, _) = watch::channel(config.scan_interval());
        let (rate_limit, _) = watch::channel(config.rate_limit());
        let trigger = Arc::new(Notify::new());

        Reloader {
            config,
            endpoint,
            grpc,
            otel,
            paths,
            scan_interval,
            rate_limit,
            files,
            trigger,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reloading_endpoint() {
        let tests = [
            (FactConfig::default(), FactConfig::default(), None),
            (
                FactConfig::default(),
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([127, 0, 0, 1], 8080).into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    address: Some(([127, 0, 0, 1], 8080).into()),
                    ..Default::default()
                }),
            ),
            (
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([0, 0, 0, 0], 9090).into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([127, 0, 0, 1], 8080).into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    address: Some(([127, 0, 0, 1], 8080).into()),
                    ..Default::default()
                }),
            ),
            (
                FactConfig::default(),
                FactConfig {
                    endpoint: EndpointConfig {
                        expose_metrics: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                }),
            ),
            (
                FactConfig {
                    endpoint: EndpointConfig {
                        expose_metrics: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                FactConfig {
                    endpoint: EndpointConfig {
                        expose_metrics: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    expose_metrics: Some(false),
                    ..Default::default()
                }),
            ),
            (
                FactConfig::default(),
                FactConfig {
                    endpoint: EndpointConfig {
                        health_check: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                }),
            ),
            (
                FactConfig {
                    endpoint: EndpointConfig {
                        health_check: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                FactConfig {
                    endpoint: EndpointConfig {
                        health_check: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    health_check: Some(false),
                    ..Default::default()
                }),
            ),
            (
                FactConfig::default(),
                FactConfig {
                    endpoint: EndpointConfig {
                        introspection: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                None,
            ),
            (
                FactConfig {
                    endpoint: EndpointConfig {
                        introspection: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                FactConfig {
                    endpoint: EndpointConfig {
                        introspection: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                None,
            ),
            (
                FactConfig::default(),
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([127, 0, 0, 1], 8080).into()),
                        introspection: Some(true),
                        expose_metrics: Some(true),
                        health_check: Some(true),
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    address: Some(([127, 0, 0, 1], 8080).into()),
                    introspection: None,
                    expose_metrics: Some(true),
                    health_check: Some(true),
                }),
            ),
            (
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([0, 0, 0, 0], 9090).into()),
                        introspection: Some(true),
                        expose_metrics: Some(true),
                        health_check: Some(true),
                    },
                    ..Default::default()
                },
                FactConfig {
                    endpoint: EndpointConfig {
                        address: Some(([127, 0, 0, 1], 8080).into()),
                        introspection: Some(false),
                        expose_metrics: Some(false),
                        health_check: Some(false),
                    },
                    ..Default::default()
                },
                Some(EndpointConfig {
                    address: Some(([127, 0, 0, 1], 8080).into()),
                    introspection: Some(true),
                    expose_metrics: Some(false),
                    health_check: Some(false),
                }),
            ),
        ];

        for (old, new, expected) in tests {
            let reloader = Reloader::from(old);
            let endpoint = reloader.endpoint();
            let assert_has_changed = |has_changed: bool| {
                assert!(
                    has_changed,
                    "\ninput: {:?}\nnew: {:?}",
                    reloader.config().endpoint,
                    new.endpoint
                );
            };

            reloader.send_updates(&new);

            match expected {
                Some(expected) => {
                    assert_has_changed(endpoint.has_changed().unwrap());
                    assert_eq!(*endpoint.borrow(), expected);
                }
                None => {
                    assert_has_changed(!endpoint.has_changed().unwrap());
                }
            }
        }
    }
}
