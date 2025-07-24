use std::{fs::read_to_string, path::PathBuf};

use anyhow::bail;
use fact_api::{file_activity_service_client::FileActivityServiceClient, FileActivity};
use log::warn;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
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

impl TryFrom<PathBuf> for Certs {
    type Error = anyhow::Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
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
    tx: mpsc::Sender<FileActivity>,
}

impl Client {
    pub fn start(url: &str, certs: Option<PathBuf>) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(100);
        let rx = ReceiverStream::new(rx);
        let url = url.to_owned();

        tokio::spawn(async move {
            let mut channel = Channel::from_shared(url).unwrap();
            if let Some(certs) = certs.as_ref() {
                let certs: Certs = certs.clone().try_into().unwrap();
                let tls = ClientTlsConfig::new()
                    .domain_name("sensor.stackrox.svc")
                    .ca_certificate(certs.ca.clone())
                    .identity(certs.identity.clone());
                channel = channel.tls_config(tls).unwrap();
            }

            let channel = channel.connect().await.unwrap();
            let mut client =
                FileActivityServiceClient::with_interceptor(channel, UserAgentInterceptor {});

            if let Err(e) = client.communicate(rx).await {
                warn!("Communication failed: {e}");
            }
        });
        Ok(Client { tx })
    }

    pub async fn send(&mut self, event: Event) -> anyhow::Result<()> {
        if let Err(e) = self.tx.send(event.into()).await {
            bail!("Failed to send event: {e}");
        }
        Ok(())
    }
}
