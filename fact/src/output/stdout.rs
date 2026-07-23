use log::{info, warn};
use tokio::{
    sync::{broadcast::error::RecvError, watch},
    task::JoinSet,
};

use crate::{metrics::EventCounter, output::EventReceiver};

pub struct Client {
    rx: EventReceiver,
    running: watch::Receiver<bool>,
    metrics: EventCounter,
}

impl Client {
    pub fn new(rx: EventReceiver, running: watch::Receiver<bool>, metrics: EventCounter) -> Self {
        Client {
            rx,
            running,
            metrics,
        }
    }

    pub fn start(mut self, task_set: &mut JoinSet<anyhow::Result<()>>) {
        task_set.spawn(async move {
            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let event = match event {
                            Ok(event) => event,
                            Err(RecvError::Closed) => {
                                info!("Channel closed, stopping stdout output...");
                                return Ok(());
                            }
                            Err(RecvError::Lagged(n)) => {
                                self.metrics.dropped_n(n);
                                warn!("Stdout worker dropped {n} events");
                                continue;
                            }
                        };
                        match serde_json::to_string(&*event) {
                            Ok(event) => {
                                self.metrics.added();
                                println!("{event}");
                            }
                            Err(e) => {
                                self.metrics.dropped();
                                warn!("There was an error serializing an event: {e}")
                            }
                        }
                    },
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            info!("Stopping stdout output...");
                            return Ok(());
                        }
                    }
                }
            }
        });
    }
}
