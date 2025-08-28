use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use tokio::{
    sync::{broadcast, watch},
    task::JoinHandle,
};

use crate::{config::FactConfig, event::Event, grpc};

pub struct Output {
    running: watch::Receiver<bool>,
    rx: broadcast::Receiver<Arc<Event>>,
}

impl Output {
    pub fn new(running: watch::Receiver<bool>, rx: broadcast::Receiver<Arc<Event>>) -> Self {
        Output { running, rx }
    }

    pub fn start(&self, config: &FactConfig) -> anyhow::Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        if let Some(url) = config.url.as_ref() {
            let h = self.start_grpc(url.clone(), config.certs.clone())?;
            handles.push(h)
        };

        if handles.is_empty() || config.json {
            handles.push(self.start_stdout()?);
        }

        Ok(handles)
    }

    fn clone_receivers(&self) -> (watch::Receiver<bool>, broadcast::Receiver<Arc<Event>>) {
        let running = self.running.clone();
        let rx = self.rx.resubscribe();
        (running, rx)
    }

    fn start_grpc(&self, url: String, certs: Option<PathBuf>) -> anyhow::Result<JoinHandle<()>> {
        let mut client = grpc::Client::start(&url, certs)?;
        let (mut running, mut rx) = self.clone_receivers();

        let h = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        let event = Arc::unwrap_or_clone(event.expect("Failed to receive event"));
                        client.send(event).await.unwrap();
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            info!("Stopping gRPC output...");
                            return;
                        }
                    }
                }
            }
        });
        Ok(h)
    }

    fn start_stdout(&self) -> anyhow::Result<JoinHandle<()>> {
        let (mut running, mut rx) = self.clone_receivers();
        let h = tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        let event = event.expect("Failed to receive event");
                        match serde_json::to_string(&*event) {
                            Ok(e) => println!("{e}"),
                            Err(e) => warn!("There was an error serializing an event: {e}"),
                        }
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            info!("Stopping stdout output...");
                            return;
                        }
                    }
                }
            }
        });
        Ok(h)
    }
}
