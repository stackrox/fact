//! Best-effort image enrichment. Owns the CRI client, cache, and worker;
//! event delivery never waits for a runtime lookup.
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::{net::UnixStream, sync::mpsc, task::JoinHandle, time::Instant};
use tonic::{Request, client::Grpc, transport::Channel, transport::Endpoint};
use tower::service_fn;

const CAPACITY: usize = 128;
const MAX_CONTAINERS: usize = 1024;
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct Enricher {
    ids: mpsc::Sender<String>,
    worker: JoinHandle<()>,
    cache: Arc<Mutex<HashMap<String, CachedImage>>>,
}

struct CachedImage {
    expires: Instant,
    image: Option<String>,
}

impl Enricher {
    pub(crate) fn from_env() -> Option<Self> {
        let socket = PathBuf::from(std::env::var_os("FACT_CRI_SOCKET")?);
        if !socket.is_absolute() {
            warn!("FACT_CRI_SOCKET must be an absolute path; CRI image enrichment disabled");
            return None;
        }
        // The path is in Fact's filesystem, e.g. /host/run/crio/crio.sock.
        Some(Self::new(socket))
    }

    fn new(socket: PathBuf) -> Self {
        let (ids, mut pending) = mpsc::channel::<String>(CAPACITY);
        let cache = Arc::new(Mutex::new(HashMap::<String, CachedImage>::new()));
        let worker_cache = cache.clone();
        let worker = tokio::spawn(async move {
            let mut client = client(socket);
            while let Some(id) = pending.recv().await {
                match container_status(&mut client, &id).await {
                    Ok(status) => {
                        if let Some(entry) = worker_cache.lock().unwrap().get_mut(&id) {
                            entry.image = status.image_identity();
                        }
                    }
                    Err(error) => debug!("CRI image unavailable for {id}: {error:#}"),
                }
            }
        });
        Self { ids, worker, cache }
    }

    pub(crate) fn image(&self, id: &str) -> Option<String> {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get(id).filter(|entry| entry.expires > now) {
            return entry.image.clone();
        }
        cache.retain(|_, entry| entry.expires > now);
        // Reserve pending entries too, so repeated events do not flood the queue.
        // Failed lookups remain cached until expiry, limiting retry pressure.
        if cache.len() < MAX_CONTAINERS && self.ids.try_send(id.to_owned()).is_ok() {
            cache.insert(
                id.to_owned(),
                CachedImage {
                    expires: now + REFRESH_INTERVAL,
                    image: None,
                },
            );
        }
        None
    }
}

impl Drop for Enricher {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn client(socket: PathBuf) -> Grpc<Channel> {
    // The URI is required by tonic but all connections use the Unix socket.
    let channel = Endpoint::from_static("http://[::]:50051").connect_with_connector_lazy(
        service_fn(move |_| {
            let socket = socket.clone();
            async move { UnixStream::connect(socket).await.map(TokioIo::new) }
        }),
    );
    Grpc::new(channel)
}

async fn container_status(client: &mut Grpc<Channel>, id: &str) -> anyhow::Result<ContainerStatus> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        client.ready().await?;
        let response: ContainerStatusResponse = client
            .unary(
                Request::new(ContainerStatusRequest {
                    container_id: id.to_owned(),
                    verbose: false,
                }),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/runtime.v1.RuntimeService/ContainerStatus",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await?
            .into_inner();
        let status = response
            .status
            .ok_or_else(|| anyhow::anyhow!("missing status"))?;
        anyhow::ensure!(status.id == id, "container ID mismatch");
        Ok(status)
    })
    .await?
}

// Wire-compatible subset of Kubernetes CRI v1 (api.proto). Unknown fields are
// ignored. Keep this read-only client limited to ContainerStatus; verbose info,
// labels/annotations, mounts, and other RPCs are intentionally not collected.
// https://github.com/kubernetes/cri-api/blob/v0.30.0/pkg/apis/runtime/v1/api.proto
#[derive(Clone, PartialEq, prost::Message)]
struct ContainerStatusRequest {
    #[prost(string, tag = "1")]
    container_id: String,
    #[prost(bool, tag = "2")]
    verbose: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ContainerStatusResponse {
    #[prost(message, optional, tag = "1")]
    status: Option<ContainerStatus>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ContainerStatus {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "9")]
    image_ref: String,
    #[prost(string, tag = "17")]
    image_id: String,
}

impl ContainerStatus {
    fn image_identity(self) -> Option<String> {
        let image = if self.image_id.is_empty() {
            self.image_ref
        } else {
            self.image_id
        };
        (!image.is_empty()).then_some(image)
    }
}

#[cfg(test)]
mod tests;
