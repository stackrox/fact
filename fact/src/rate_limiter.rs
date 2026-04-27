use governor::{
    Quota,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use log::warn;
use std::num::NonZeroU32;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::event::Event;
use crate::metrics::EventCounter;

pub struct RateLimiter {
    // the governor::RateLimiter handles the actual rate limiting. For now
    // we use NotKeyed because we want to globally rate limit all events
    // but in the future we could introduce a key to limit in more flexible ways
    // (using a String; process name, container id, whatever)
    limiter: Option<governor::RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    rx: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    rate_config: watch::Receiver<u64>,
    running: watch::Receiver<bool>,
    metrics: EventCounter,
}

impl RateLimiter {
    pub fn new(
        rx: mpsc::Receiver<Event>,
        rate_config: watch::Receiver<u64>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Event>)> {
        let limiter = Self::build_limiter(*rate_config.borrow());
        let (tx, output) = mpsc::channel(100);

        let limiter = RateLimiter {
            limiter,
            rx,
            tx,
            rate_config,
            running,
            metrics,
        };

        Ok((limiter, output))
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

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(event) = event else { break;};

                        if let Some(limiter) = &self.limiter && limiter.check().is_err() {
                            self.metrics.dropped();
                            continue;
                        }

                        self.metrics.added();
                        if let Err(e) = self.tx.send(event).await {
                            warn!("RateLimiter failed to forward event: {e:?}");
                            self.metrics.errored();
                        }
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
