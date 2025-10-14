use std::{fs::read_to_string, path::Path, time::Duration};

use anyhow::bail;
use fact_api::{file_activity_service_client::FileActivityServiceClient, FileActivity};
use log::{debug, info, warn};
use tokio::{sync::broadcast, time::sleep};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tonic::{
    metadata::MetadataValue,
    service::Interceptor,
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
};

use crate::event::Event;

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

pub struct Client {
    tx: broadcast::Sender<FileActivity>,
}

impl Client {
    pub fn start(url: &str, certs: Option<&Path>) -> anyhow::Result<Self> {
        let (tx, _) = broadcast::channel(100);
        let url = url.to_owned();
        let certs = certs.map(Certs::try_from).transpose()?;
        let mut channel = Channel::from_shared(url)?;
        if let Some(certs) = certs {
            let tls = ClientTlsConfig::new()
                .domain_name("sensor.stackrox.svc")
                .ca_certificate(certs.ca.clone())
                .identity(certs.identity.clone());
            channel = channel.tls_config(tls)?;
        }
        // Create a local clone of the Sender to allow for reconnects
        let local_tx = tx.clone();

        tokio::spawn(async move {
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

                let mut client =
                    FileActivityServiceClient::with_interceptor(channel, UserAgentInterceptor {});

                let rx = BroadcastStream::new(local_tx.subscribe()).filter_map(|v| {
                    if let Err(e) = &v {
                        warn!("Broadcast stream lagged: {e}");
                    }
                    v.ok()
                });

                if let Err(e) = client.communicate(rx).await {
                    warn!("Communication failed: {e}");
                }
            }
        });
        Ok(Client { tx })
    }

    pub fn send(&mut self, event: Event) -> anyhow::Result<()> {
        if let Err(e) = self.tx.send(event.into()) {
            bail!("Failed to send event: {e}");
        }
        Ok(())
    }
}
