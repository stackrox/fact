use std::{sync::Arc, time::Duration};

use anyhow::bail;
use fact_api::file_activity_service_client::FileActivityServiceClient;
use hyper_rustls::HttpsConnectorBuilder;
use log::{debug, info, warn};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore,
};
use tokio::{
    sync::{broadcast, watch},
    time::sleep,
};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamExt,
};
use tonic::{metadata::MetadataValue, service::Interceptor, transport::Channel};

use crate::{config::GrpcConfig, event::Event, metrics::EventCounter};

struct UserAgentInterceptor {}

impl Interceptor for UserAgentInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        request
            .metadata_mut()
            .insert("user-agent", MetadataValue::from_static("Rox SFA Agent"));
        Ok(request)
    }
}

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
                    Err(e) => warn!("gRPC error: {e}"),
                }
            }
        });
    }

    fn get_tls_config(&self) -> anyhow::Result<Option<ClientConfig>> {
        match self.config.borrow().certs() {
            Some(certs) => {
                let mut cert_store = RootCertStore::empty();
                for cert in CertificateDer::pem_file_iter(certs.join("ca.pem"))? {
                    cert_store.add(cert?)?;
                }
                let client_cert = CertificateDer::pem_file_iter(certs.join("cert.pem"))?
                    .collect::<Result<Vec<_>, _>>()?;
                let client_key = PrivateKeyDer::from_pem_file(certs.join("key.pem"))?;
                let client = ClientConfig::builder()
                    .with_root_certificates(cert_store)
                    .with_client_auth_cert(client_cert, client_key)?;
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn create_channel(&self) -> anyhow::Result<Channel> {
        let url = match self.config.borrow().url() {
            Some(url) => url.to_string(),
            None => bail!("Attempting to run gRPC client with no URL"),
        };
        let channel = Channel::from_shared(url)?;
        match self.get_tls_config()? {
            Some(config) => {
                if !config.fips() {
                    // FIPS is enabled at compile time, we should not
                    // hit this condition.
                    panic!("FIPS mode is not enabled");
                }

                let connector = HttpsConnectorBuilder::new()
                    .with_tls_config(config)
                    .https_only()
                    .enable_http2()
                    .build();

                let channel = channel.connect_with_connector(connector).await?;
                Ok(channel)
            }
            None => Ok(channel.connect().await?),
        }
    }

    async fn run(&mut self) -> anyhow::Result<bool> {
        loop {
            info!("Attempting to connect to gRPC server...");
            let channel = match self.create_channel().await {
                Ok(channel) => channel,
                Err(e) => {
                    debug!("Failed to connect to server: {e}");
                    sleep(Duration::new(1, 0)).await;
                    continue;
                }
            };
            info!("Successfully connected to gRPC server");

            let mut client =
                FileActivityServiceClient::with_interceptor(channel, UserAgentInterceptor {});

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
                        Err(e) => warn!("gRPC stream error: {e}"),
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
