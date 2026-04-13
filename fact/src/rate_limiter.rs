use governor::{
    Quota,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, error::RecvError},
    watch,
};
use tokio::task::JoinHandle;

use crate::event::Event;
use crate::metrics::EventCounter;

pub struct RateLimiter {
    // the governor::RateLimiter handles the actual rate limiting. For now
    // we use NotKeyed because we want to globally rate limit all events
    // but in the future we could introduce a key to limit in more flexible ways
    // (using a String; process name, container id, whatever)
    limiter: Option<governor::RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    rx: broadcast::Receiver<Arc<Event>>,
    tx: broadcast::Sender<Arc<Event>>,
    rate_config: watch::Receiver<u64>,
    running: watch::Receiver<bool>,
    metrics: EventCounter,
}

impl RateLimiter {
    pub fn new(
        rx: broadcast::Receiver<Arc<Event>>,
        rate_config: watch::Receiver<u64>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
    ) -> anyhow::Result<Self> {
        let limiter = Self::build_limiter(*rate_config.borrow());
        let (tx, _) = broadcast::channel(100);

        Ok(RateLimiter {
            limiter,
            rx,
            tx,
            rate_config,
            running,
            metrics,
        })
    }

    fn build_limiter(
        rate: u64,
    ) -> Option<governor::RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        if rate == 0 {
            None
        } else {
            let rate = NonZeroU32::new(rate as u32).expect("rate > 0");
            Some(governor::RateLimiter::direct(Quota::per_second(rate)))
        }
    }

    fn reload_limiter(&mut self) -> anyhow::Result<()> {
        let rate = *self.rate_config.borrow();
        self.limiter = Self::build_limiter(rate);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let event = match event {
                            Ok(e) => e,
                            Err(RecvError::Lagged(_)) => continue,
                            Err(RecvError::Closed) => break,
                        };

                        if let Some(limiter) = &self.limiter && limiter.check().is_err() {
                            self.metrics.dropped();
                            continue;
                        }

                        self.metrics.added();
                        let _ = self.tx.send(event);
                    },
                    _ = self.rate_config.changed() => {
                        self.reload_limiter()?;
                    },
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            break;
                        }
                    },
                }
            }
            Ok(())
        })
    }
}
