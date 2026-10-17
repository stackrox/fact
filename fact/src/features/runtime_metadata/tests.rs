use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Response, Status, body::Body, codegen::http, server::NamedService};

use super::*;

// Exercise real HTTP/2 gRPC over a Unix socket, including the RPC path, request
// ID, verbose flag, missing containers, and a server that does not respond.
#[derive(Clone)]
struct FakeRuntime {
    reply: Arc<Result<Option<ContainerStatus>, Status>>,
    delay: Duration,
    calls: mpsc::UnboundedSender<ContainerStatusRequest>,
}

impl NamedService for FakeRuntime {
    const NAME: &'static str = "runtime.v1.RuntimeService";
}

impl tower::Service<http::Request<Body>> for FakeRuntime {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(
            request.uri().path(),
            "/runtime.v1.RuntimeService/ContainerStatus"
        );
        let service = self.clone();
        Box::pin(async move {
            Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                .unary(service, request)
                .await)
        })
    }
}

impl tonic::server::UnaryService<ContainerStatusRequest> for FakeRuntime {
    type Response = ContainerStatusResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send>>;

    fn call(&mut self, request: Request<ContainerStatusRequest>) -> Self::Future {
        self.calls.send(request.into_inner()).unwrap();
        let reply = self.reply.clone();
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(Response::new(ContainerStatusResponse {
                status: (*reply).clone()?,
            }))
        })
    }
}

struct Server {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
    calls: mpsc::UnboundedReceiver<ContainerStatusRequest>,
}

impl Server {
    async fn new(reply: Result<Option<ContainerStatus>, Status>, delay: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cri.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (calls, received) = mpsc::unbounded_channel();
        let service = FakeRuntime {
            reply: Arc::new(reply),
            delay,
            calls,
        };
        let task = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(UnixListenerStream::new(listener)),
        );
        Self {
            _dir: dir,
            socket,
            task,
            calls: received,
        }
    }

    async fn request(&mut self) -> ContainerStatusRequest {
        tokio::time::timeout(Duration::from_secs(3), self.calls.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn status() -> ContainerStatus {
    ContainerStatus {
        id: "a".repeat(64),
        image_ref: "example/app@sha256:abcd".into(),
        image_id: "sha256:1234".into(),
    }
}

#[tokio::test]
async fn reads_status_over_unix_socket() {
    let expected = status();
    let mut server = Server::new(Ok(Some(expected.clone())), Duration::ZERO).await;
    let actual = container_status(&mut client(server.socket.clone()), &expected.id)
        .await
        .unwrap();
    assert_eq!(actual, expected);
    let request = server.request().await;
    assert_eq!(request.container_id, expected.id);
    assert!(!request.verbose);
}

#[tokio::test]
async fn rejects_missing_or_mismatched_status_and_rpc_errors() {
    for (reply, reason) in [
        (Ok(None), "missing status"),
        (
            Ok(Some(ContainerStatus::default())),
            "container ID mismatch",
        ),
        (Err(Status::not_found("removed")), "removed"),
        (
            Err(Status::unavailable("runtime stopped")),
            "runtime stopped",
        ),
    ] {
        let server = Server::new(reply, Duration::ZERO).await;
        let error = container_status(&mut client(server.socket.clone()), &status().id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(reason), "{error:#}");
    }
}

#[tokio::test]
async fn bounds_slow_requests_and_unavailable_sockets() {
    let server = Server::new(Ok(Some(status())), REQUEST_TIMEOUT * 3).await;
    let error = container_status(&mut client(server.socket.clone()), &status().id)
        .await
        .unwrap_err();
    assert!(error.is::<tokio::time::error::Elapsed>(), "{error:#}");
    assert!(
        container_status(
            &mut client(server.socket.with_file_name("missing.sock")),
            &status().id
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn suppresses_repeated_lookups_without_blocking_observation() {
    let mut server = Server::new(Err(Status::not_found("removed")), Duration::ZERO).await;
    let observer = Enricher::new(server.socket.clone());
    observer.image(&status().id);
    observer.image(&status().id);
    observer.image(&"b".repeat(64));
    assert_eq!(server.request().await.container_id, status().id);
    assert_eq!(server.request().await.container_id, "b".repeat(64));
    // No await in observe(): even a saturated queue cannot stall the caller.
    for i in 0..CAPACITY * 2 {
        observer.image(&format!("container-{i}"));
    }
    assert_eq!(observer.ids.capacity(), 0);
}

#[test]
fn selects_image_id_then_reference_and_omits_empty_identity() {
    assert_eq!(status().image_identity().as_deref(), Some("sha256:1234"));
    assert_eq!(
        ContainerStatus {
            image_id: String::new(),
            ..status()
        }
        .image_identity()
        .as_deref(),
        Some("example/app@sha256:abcd")
    );
    assert_eq!(ContainerStatus::default().image_identity(), None);
}

#[tokio::test]
async fn enriches_event_json_and_reuses_cached_image() {
    use crate::event::Event;
    use fact_ebpf::{event_t, file_activity_type_t};

    for image_id in ["sha256:1234", ""] {
        let reply = ContainerStatus {
            image_id: image_id.into(),
            ..status()
        };
        let expected = reply.clone().image_identity().unwrap();
        let mut server = Server::new(Ok(Some(reply)), Duration::ZERO).await;
        let enricher = Enricher::new(server.socket.clone());
        let mut raw = event_t {
            type_: file_activity_type_t::FILE_ACTIVITY_CREATION,
            ..Default::default()
        };
        for (dest, src) in raw
            .process
            .memory_cgroup
            .iter_mut()
            .zip(format!("/kubepods/{}", status().id).bytes())
        {
            *dest = src as _;
        }
        let mut event = Event::try_from(&raw).unwrap();
        event.enrich_image(&enricher);
        assert!(
            serde_json::to_value(&event).unwrap()["process"]
                .get("container_image")
                .is_none()
        );
        assert_eq!(server.request().await.container_id, status().id);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                event.enrich_image(&enricher);
                if serde_json::to_value(&event).unwrap()["process"]["container_image"] == expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..10 {
            event.enrich_image(&enricher);
        }
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["process"]["container_image"], expected);
        assert_eq!(json["process"]["container_id"], &status().id[..12]);
        #[cfg(feature = "otel")]
        {
            use opentelemetry::logs::AnyValue;
            let AnyValue::Map(fields) = AnyValue::from(event.clone()) else {
                panic!("event map")
            };
            let Some(AnyValue::Map(process)) = fields.get("process") else {
                panic!("process map")
            };
            let Some(AnyValue::String(image)) = process.get("container_image") else {
                panic!("image identity")
            };
            assert_eq!(image.as_str(), expected);
        }
        assert!(server.calls.try_recv().is_err());
        assert_eq!(enricher.ids.capacity(), CAPACITY);
        // Replay keeps recorded enrichment without querying the current runtime.
        let mut replay: Event = serde_json::from_value(json.clone()).unwrap();
        let disconnected = Enricher::new(server.socket.with_file_name("missing.sock"));
        replay.enrich_image(&disconnected);
        assert_eq!(
            serde_json::to_value(&replay).unwrap()["process"]["container_image"],
            json["process"]["container_image"]
        );
        assert!(disconnected.cache.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn bounds_cache_and_retries_after_expiry() {
    let mut server = Server::new(Err(Status::not_found("removed")), Duration::ZERO).await;
    let enricher = Enricher::new(server.socket.clone());
    assert!(enricher.image(&status().id).is_none());
    server.request().await;
    // A failure/pending entry suppresses another RPC until its retry window ends.
    assert!(enricher.image(&status().id).is_none());
    enricher
        .cache
        .lock()
        .unwrap()
        .get_mut(&status().id)
        .unwrap()
        .expires = Instant::now();
    assert!(enricher.image(&status().id).is_none());
    server.request().await;
    {
        let mut cache = enricher.cache.lock().unwrap();
        cache.clear();
        for i in 0..MAX_CONTAINERS {
            cache.insert(
                i.to_string(),
                CachedImage {
                    expires: Instant::now() + REFRESH_INTERVAL,
                    image: None,
                },
            );
        }
    }
    assert!(enricher.image("over-capacity").is_none());
    assert_eq!(enricher.cache.lock().unwrap().len(), MAX_CONTAINERS);
    assert_eq!(enricher.ids.capacity(), CAPACITY);
}
