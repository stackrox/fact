//! Best-effort CRI diagnostics. This module owns the socket, worker, and lookup
//! budget; the event pipeline only supplies a container ID without waiting.
use std::{collections::HashMap, path::PathBuf, time::Duration};

use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::{net::UnixStream, sync::mpsc, task::JoinHandle, time::Instant};
use tonic::{Request, client::Grpc, transport::Channel, transport::Endpoint};
use tower::service_fn;

const CAPACITY: usize = 128;
const MAX_CONTAINERS: usize = 1024;
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct Observer {
    ids: mpsc::Sender<String>,
    worker: JoinHandle<()>,
}

impl Observer {
    pub(crate) fn from_env() -> Option<Self> {
        let socket = PathBuf::from(std::env::var_os("FACT_CRI_SOCKET")?);
        if !socket.is_absolute() {
            warn!("FACT_CRI_SOCKET must be an absolute path; CRI diagnostics disabled");
            return None;
        }
        if !log::log_enabled!(log::Level::Debug) {
            return None;
        }
        // The path is in Fact's filesystem, e.g. /host/run/crio/crio.sock.
        Some(Self::new(socket))
    }

    fn new(socket: PathBuf) -> Self {
        let (ids, mut pending) = mpsc::channel::<String>(CAPACITY);
        let worker = tokio::spawn(async move {
            let mut client = client(socket);
            let mut recent = HashMap::new();
            while let Some(id) = pending.recv().await {
                let now = Instant::now();
                // Expire both successful and failed lookups. Never retain stale
                // lifecycle state indefinitely or retry on every file event.
                recent.retain(|_, until| *until > now);
                if recent.contains_key(&id) || recent.len() >= MAX_CONTAINERS {
                    continue;
                }
                recent.insert(id.clone(), now + REFRESH_INTERVAL);
                match container_status(&mut client, &id).await {
                    Ok(status) => debug!("CRI ContainerStatus: {status:?}"),
                    Err(error) => debug!("CRI ContainerStatus unavailable for {id}: {error:#}"),
                }
            }
        });
        Self { ids, worker }
    }

    pub(crate) fn observe(&self, id: &str) {
        // Only IDs extracted from live cgroups are eligible. Replay data does
        // not populate that field. A full queue drops diagnostics, not events.
        let _ = self.ids.try_send(id.to_owned());
    }
}

impl Drop for Observer {
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
    #[prost(message, optional, tag = "2")]
    metadata: Option<ContainerMetadata>,
    #[prost(enumeration = "ContainerState", tag = "3")]
    state: i32,
    #[prost(int64, tag = "4")]
    created_at: i64,
    #[prost(int64, tag = "5")]
    started_at: i64,
    #[prost(int64, tag = "6")]
    finished_at: i64,
    #[prost(int32, tag = "7")]
    exit_code: i32,
    #[prost(message, optional, tag = "8")]
    image: Option<ImageSpec>,
    #[prost(string, tag = "9")]
    image_ref: String,
    #[prost(string, tag = "10")]
    reason: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ContainerMetadata {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(uint32, tag = "2")]
    attempt: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ImageSpec {
    #[prost(string, tag = "1")]
    image: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum ContainerState {
    Created = 0,
    Running = 1,
    Exited = 2,
    Unknown = 3,
}

#[cfg(test)]
mod tests;
