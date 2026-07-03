use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use fact_api::file_activity_service_client::FileActivityServiceClient;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use log::{info, warn};
use native_tls::{Certificate, Identity};
use openssl::{ec::EcKey, pkey::PKey};
use tokio::{
    fs,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::sleep,
};
use tokio_stream::{
    StreamExt,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};
use tonic::transport::Channel;

use crate::{
    config::{BackoffConfig, GrpcConfig},
    metrics::EventCounter,
    output::EventReceiver,
};

struct Backoff {
    initial: Duration,
    current: Duration,
    max: Duration,
    jitter: bool,
    multiplier: f64,
    retries_max: u64,
    retries_curr: u64,
}

impl Backoff {
    fn new(
        initial: Duration,
        max: Duration,
        jitter: bool,
        multiplier: f64,
        retries_max: u64,
    ) -> Self {
        let initial = if initial >= max {
            warn!(
                "Invalid initial value: {} >= {}",
                initial.as_secs_f64(),
                max.as_secs_f64()
            );
            max
        } else {
            initial
        };

        Self {
            initial,
            current: initial,
            max,
            jitter,
            multiplier,
            retries_max,
            retries_curr: 0,
        }
    }

    fn next(&mut self) -> Option<Duration> {
        if self.retries_max != 0 {
            if self.retries_curr >= self.retries_max {
                return None;
            }
            self.retries_curr += 1;
        }

        let delay = self.current.min(self.max);
        self.current = self.current.mul_f64(self.multiplier).min(self.max);
        let delay = if self.jitter {
            let nanos = rand::random_range(0..=delay.as_nanos() as u64);
            Duration::from_nanos(nanos)
        } else {
            delay
        };

        Some(delay)
    }

    fn reset(&mut self) {
        self.current = self.initial;
        self.retries_curr = 0;
    }
}

impl From<&BackoffConfig> for Backoff {
    fn from(value: &BackoffConfig) -> Self {
        Backoff::new(
            value.initial(),
            value.max(),
            value.jitter(),
            value.multiplier(),
            value.retries(),
        )
    }
}

pub struct Client {
    subscriber: mpsc::Sender<oneshot::Sender<EventReceiver>>,
    running: watch::Receiver<bool>,
    config: watch::Receiver<GrpcConfig>,
    metrics: EventCounter,
}

impl Client {
    pub fn new(
        subscriber: mpsc::Sender<oneshot::Sender<EventReceiver>>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
        config: watch::Receiver<GrpcConfig>,
    ) -> Self {
        Client {
            subscriber,
            running,
            config,
            metrics,
        }
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            loop {
                let res = if self.is_enabled() {
                    self.run().await
                } else {
                    self.idle().await
                };

                match res {
                    Ok(true) => info!("Reloading gRPC configuration..."),
                    Ok(false) => {
                        info!("Stopping gRPC output...");
                        break;
                    }
                    Err(e) => bail!("gRPC error: {e:?}"),
                }
            }
            Ok(())
        })
    }

    async fn get_connector(&self) -> anyhow::Result<Option<HttpsConnector<HttpConnector>>> {
        let certs = {
            let config = self.config.borrow();
            let Some(certs) = config.certs() else {
                return Ok(None);
            };
            certs.to_owned()
        };
        let (ca, cert, key) = tokio::try_join!(
            fs::read(certs.join("ca.pem")),
            fs::read(certs.join("cert.pem")),
            fs::read(certs.join("key.pem")),
        )?;
        let ca = Certificate::from_pem(&ca).context("Failed to parse CA")?;

        // The key is in PKCS#1 format using EC algorithm, we need it
        // in PKCS#8 format for native-tls, so we convert it here
        let key = EcKey::private_key_from_pem(&key)?;
        let key = PKey::from_ec_key(key)?;
        let key = key.private_key_to_pem_pkcs8()?;

        let id = Identity::from_pkcs8(&cert, &key).context("Failed to create TLS identity")?;
        let connector = native_tls::TlsConnector::builder()
            .add_root_certificate(ca)
            .identity(id)
            .request_alpns(&["h2"])
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);

        // Wrap the TLS connector into the final HTTPs connector
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut connector = HttpsConnector::from((http, connector));
        connector.https_only(true);

        Ok(Some(connector))
    }

    async fn create_channel(
        &self,
        connector: Option<HttpsConnector<HttpConnector>>,
    ) -> anyhow::Result<Channel> {
        let url = match self.config.borrow().url() {
            Some(url) => url.to_string(),
            None => bail!("Attempting to run gRPC client with no URL"),
        };
        let channel = Channel::from_shared(url)?;
        let channel = match connector {
            Some(connector) => channel.connect_with_connector(connector).await?,
            None => {
                warn!("Using unencrypted gRPC channel");
                channel.connect().await?
            }
        };
        Ok(channel)
    }

    async fn run(&mut self) -> anyhow::Result<bool> {
        let mut backoff = Backoff::from(&self.config.borrow().backoff);
        loop {
            // Re-read certs on each connection attempt so rotated certificates
            // on disk are picked up on the next reconnect.
            let connector = self.get_connector().await?;
            info!("Attempting to connect to gRPC server...");
            let channel = match self.create_channel(connector).await {
                Ok(channel) => channel,
                Err(e) => {
                    let Some(delay) = backoff.next() else {
                        bail!(
                            "Failed to connect to server: Reconnection attempts exhausted: {e:?}"
                        );
                    };
                    warn!("Failed to connect to server: {e:?}\nRetrying in {delay:?}");
                    sleep(delay).await;
                    continue;
                }
            };
            info!("Successfully connected to gRPC server");
            backoff.reset();

            let mut client = FileActivityServiceClient::new(channel);

            let metrics = self.metrics.clone();
            let (tx, rx) = oneshot::channel();
            self.subscriber.send(tx).await?;
            let rx = rx.await?;
            let rx = BroadcastStream::new(rx).filter_map(move |event| match event {
                Ok(event) => {
                    metrics.added();
                    let event = Arc::unwrap_or_clone(event);
                    Some(event.into())
                }
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    warn!("gRPC stream lagged, dropped {n} events");
                    metrics.dropped_n(n);
                    None
                }
            });

            tokio::select! {
                res = client.communicate(rx) => {
                    match res {
                        Ok(_) => info!("gRPC stream ended"),
                        Err(e) => warn!("gRPC stream error: {e:?}"),
                    }
                }
                _ = self.config.changed() => return Ok(true),
                _ = self.running.changed() => return Ok(*self.running.borrow()),
            }
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.config.borrow().url().is_some()
    }

    async fn idle(&mut self) -> anyhow::Result<bool> {
        tokio::select! {
            _ = self.config.changed() => Ok(true),
            _ = self.running.changed() => Ok(*self.running.borrow()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_exponential_2x() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            false,
            2.0,
            0,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
        assert_eq!(b.next(), Some(Duration::from_secs(4)));
        assert_eq!(b.next(), Some(Duration::from_secs(8)));
        assert_eq!(b.next(), Some(Duration::from_secs(16)));
        assert_eq!(b.next(), Some(Duration::from_secs(32)));
    }

    #[test]
    fn backoff_default_multiplier() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            false,
            1.5,
            0,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_millis(1500)));
        assert_eq!(b.next(), Some(Duration::from_millis(2250)));
        assert_eq!(b.next(), Some(Duration::from_millis(3375)));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut b = Backoff::new(
            Duration::from_secs(32),
            Duration::from_secs(60),
            false,
            2.0,
            0,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(32)));
        assert_eq!(b.next(), Some(Duration::from_secs(60)));
        assert_eq!(b.next(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn backoff_reset() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            false,
            2.0,
            0,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
        assert_eq!(b.next(), Some(Duration::from_secs(4)));
        b.reset();
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn backoff_jitter_within_range() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            true,
            1.5,
            0,
        );
        let mut expected_max = Duration::from_secs(1);
        for _ in 0..100 {
            let delay = b.next().expect("retries exhausted");
            assert!(
                delay <= expected_max,
                "delay {delay:?} exceeded expected max {expected_max:?}"
            );
            let nanos = expected_max.as_nanos() as u64 * 1500 / 1000;
            expected_max = Duration::from_nanos(nanos).min(Duration::from_secs(60));
        }
    }

    #[test]
    fn backoff_jitter_reset() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            true,
            1.5,
            0,
        );
        for _ in 0..5 {
            b.next();
        }
        b.reset();
        let delay = b.next().expect("retries exhausted");
        assert!(
            delay <= Duration::from_secs(1),
            "delay {delay:?} exceeded 1s after reset"
        );
    }

    #[test]
    fn backoff_reconnection_give_up() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            false,
            2.0,
            3,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
        assert_eq!(b.next(), Some(Duration::from_secs(4)));
        assert_eq!(b.next(), None);
    }

    #[test]
    fn backoff_reconnection_reset() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            false,
            2.0,
            3,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
        b.reset();
        assert_eq!(b.next(), Some(Duration::from_secs(1)));
        assert_eq!(b.next(), Some(Duration::from_secs(2)));
        assert_eq!(b.next(), Some(Duration::from_secs(4)));
        assert_eq!(b.next(), None);
    }

    #[test]
    fn backoff_initial_greater_than_max() {
        let mut b = Backoff::new(
            Duration::from_secs(120),
            Duration::from_secs(60),
            false,
            2.0,
            0,
        );
        assert_eq!(b.next(), Some(Duration::from_secs(60)));
        assert_eq!(b.next(), Some(Duration::from_secs(60)));
        assert_eq!(b.next(), Some(Duration::from_secs(60)));
    }
}
