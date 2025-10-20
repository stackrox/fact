use std::sync::Arc;

use log::{info, warn};
use tokio::sync::{
    broadcast::{self, error::RecvError},
    watch,
};

use crate::{event::Event, metrics::EventCounter};

pub struct Client {
    rx: broadcast::Receiver<Arc<Event>>,
    running: watch::Receiver<bool>,
    metrics: EventCounter,
}

impl Client {
    pub fn new(
        rx: broadcast::Receiver<Arc<Event>>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
    ) -> Self {
        Client {
            rx,
            running,
            metrics,
        }
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let event = match event {
                            Ok(event) => event,
                            Err(RecvError::Closed) => {
                                info!("Channel closed, stopping stdout output...");
                                return;
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
                            return;
                        }
                    }
                }
            }
        });
    }
}
