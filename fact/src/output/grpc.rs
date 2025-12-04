use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use fact_api::file_activity_service_client::FileActivityServiceClient;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use log::{debug, info, warn};
use native_tls::{Certificate, Identity};
use openssl::{ec::EcKey, pkey::PKey};
use tokio::{
    fs,
    sync::{broadcast, watch},
    time::sleep,
};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamExt,
};
use tonic::transport::Channel;

use crate::{config::GrpcConfig, event::Event, metrics::EventCounter};

pub struct Client {
    rx: broadcast::Receiver<Arc<Event>>,
    running: watch::Receiver<bool>,
    config: watch::Receiver<GrpcConfig>,
    metrics: EventCounter,
}

impl Client {
    pub fn new(
        rx: broadcast::Receiver<Arc<Event>>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
        config: watch::Receiver<GrpcConfig>,
    ) -> Self {
        Client {
            rx,
            running,
            config,
            metrics,
        }
    }

    pub fn start(mut self) {
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
                    Err(e) => warn!("gRPC error: {e:?}"),
                }
            }
        });
    }

    async fn get_tls_connector(&self) -> anyhow::Result<Option<tokio_native_tls::TlsConnector>> {
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

        // The key is in PKCS#1 format using EC algorithm, we
        // need it in PKCS#8 format for native-tls, so we
        // convert it here
        let key = EcKey::private_key_from_pem(&key)?;
        let key = PKey::from_ec_key(key)?;
        let key = key.private_key_to_pem_pkcs8()?;

        let id = Identity::from_pkcs8(&cert, &key).context("Failed to create TLS identity")?;
        let connector = native_tls::TlsConnector::builder()
            .add_root_certificate(ca)
            .identity(id)
            .request_alpns(&["h2"])
            .build()?;
        Ok(Some(connector.into()))
    }

    fn get_https_connector(
        &self,
        connector: Option<tokio_native_tls::TlsConnector>,
    ) -> Option<HttpsConnector<HttpConnector>> {
        connector.map(|c| {
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            let mut connector = HttpsConnector::from((http, c));
            connector.https_only(true);
            connector
        })
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
            None => channel.connect().await?,
        };
        Ok(channel)
    }

    async fn run(&mut self) -> anyhow::Result<bool> {
        let tls_connector = self.get_tls_connector().await?;
        let connector = self.get_https_connector(tls_connector);
        loop {
            info!("Attempting to connect to gRPC server...");
            let channel = match self.create_channel(connector.clone()).await {
                Ok(channel) => channel,
                Err(e) => {
                    debug!("Failed to connect to server: {e:?}");
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            info!("Successfully connected to gRPC server");

            let mut client = FileActivityServiceClient::new(channel);

            let metrics = self.metrics.clone();
            let rx =
                BroadcastStream::new(self.rx.resubscribe()).filter_map(move |event| match event {
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
