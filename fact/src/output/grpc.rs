use std::{fs::read_to_string, path::Path, sync::Arc, time::Duration};

use anyhow::bail;
use fact_api::sensor::{
    file_activity_service_client::FileActivityServiceClient,
    signal_service_client::SignalServiceClient, SignalStreamMessage,
};
use log::{debug, info, warn};
use tokio::{
    sync::{broadcast, watch},
    time::sleep,
};
use tokio_stream::{
    wrappers::{errors::BroadcastStreamRecvError, BroadcastStream},
    StreamExt,
};
use tonic::{
    metadata::MetadataValue,
    service::Interceptor,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use crate::{config::GrpcConfig, event::Event, metrics::EventCounter};

struct Certs {
    pub ca: Certificate,
    pub identity: Identity,
}

impl TryFrom<&Path> for Certs {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let ca = read_to_string(path.join("ca.pem"))?;
        let ca = Certificate::from_pem(ca);
        let cert = read_to_string(path.join("cert.pem"))?;
        let key = read_to_string(path.join("key.pem"))?;
        let identity = Identity::from_pem(cert, key);

        Ok(Self { ca, identity })
    }
}

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

impl From<Event> for SignalStreamMessage {
    fn from(value: Event) -> Self {
        let signal = fact_api::v1::Signal::from(value);
        SignalStreamMessage {
            msg: Some(fact_api::sensor::signal_stream_message::Msg::Signal(signal)),
        }
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

    fn create_channel(&self) -> anyhow::Result<Endpoint> {
        let config = self.config.borrow();
        let Some(url) = config.url() else {
            bail!("Attempting to run gRPC client with no URL");
        };
        let url = url.to_string();
        let certs = config.certs().map(Certs::try_from).transpose()?;
        let mut channel = Channel::from_shared(url)?;
        if let Some(certs) = certs {
            let tls = ClientTlsConfig::new()
                .domain_name("sensor.stackrox.svc")
                .ca_certificate(certs.ca.clone())
                .identity(certs.identity.clone());
            channel = channel.tls_config(tls)?;
        }
        Ok(channel)
    }

    async fn run(&mut self) -> anyhow::Result<bool> {
        let channel = self.create_channel()?;
        loop {
            info!("Attempting to connect to gRPC server...");
            let channel = match channel.connect().await {
                Ok(channel) => channel,
                Err(e) => {
                    debug!("Failed to connect to server: {e}");
                    sleep(Duration::new(1, 0)).await;
                    continue;
                }
            };
            info!("Successfully connected to gRPC server");

            let mut sfa_client = FileActivityServiceClient::with_interceptor(
                channel.clone(),
                UserAgentInterceptor {},
            );
            let mut signal_client =
                SignalServiceClient::with_interceptor(channel, UserAgentInterceptor {});

            let metrics = self.metrics.clone();
            let sfa_rx =
                BroadcastStream::new(self.rx.resubscribe()).filter_map(move |event| match event {
                    Ok(event) => {
                        if !matches!(event.activity, crate::event::Activity::File(_)) {
                            return None;
                        }
                        metrics.added();
                        let event = Arc::unwrap_or_clone(event);
                        Some(event.into())
                    }
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        warn!("gRPC sfa stream lagged, dropped {n} events");
                        metrics.dropped_n(n);
                        None
                    }
                });
            let metrics = self.metrics.clone();
            let signal_rx =
                BroadcastStream::new(self.rx.resubscribe()).filter_map(move |event| match event {
                    Ok(event) => {
                        if !matches!(event.activity, crate::event::Activity::Process(_)) {
                            return None;
                        }
                        metrics.added();
                        let event = Arc::unwrap_or_clone(event);
                        Some(event.into())
                    }
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        warn!("gRPC signal stream lagged, dropped {n} events");
                        metrics.dropped_n(n);
                        None
                    }
                });

            tokio::select! {
                res = sfa_client.communicate(sfa_rx) => {
                    match res {
                        Ok(_) => info!("gRPC sfa stream ended"),
                        Err(e) => warn!("gRPC sfa stream error: {e}"),
                    }
                }
                res = signal_client.push_signals(signal_rx) => {
                    match res {
                        Ok(_) => info!("gRPC signal stream ended"),
                        Err(e) => warn!("gRPC signal stream error: {e}"),
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
