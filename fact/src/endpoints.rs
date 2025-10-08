use std::{future::Future, net::SocketAddr, pin::Pin};

use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

use crate::metrics::exporter::Exporter;
use crate::profiler::Profiler;

type ServerResponse = anyhow::Result<Response<Full<Bytes>>>;

#[derive(Clone)]
pub struct Server {
    metrics: Option<Exporter>,
    health_check: bool,
    profiler: Option<Profiler>,
}

impl Server {
    pub fn new(
        metrics: Exporter,
        expose_profiler: bool,
        expose_metrics: bool,
        health_check: bool,
    ) -> Self {
        let metrics = if expose_metrics { Some(metrics) } else { None };
        let profiler = if expose_profiler {
            Some(Profiler::new())
        } else {
            None
        };

        Server {
            metrics,
            health_check,
            profiler,
        }
    }

    pub fn start(self, mut running: watch::Receiver<bool>) -> Option<JoinHandle<()>> {
        // If there is nothing to expose, we don't run the hyper server
        if self.metrics.is_none() && self.profiler.is_none() && !self.health_check {
            return None;
        }

        let handle = tokio::spawn(async move {
            // TODO ROX-30811: Make socket and address configurable
            let addr = SocketAddr::from(([0, 0, 0, 0], 9000));
            let listener = TcpListener::bind(addr).await.unwrap();

            loop {
                tokio::select! {
                    Ok((stream, _)) = listener.accept() => {
                        let io = TokioIo::new(stream);
                        let s = self.clone();
                        tokio::spawn(async move {
                            if let Err(e) = http1::Builder::new().serve_connection(io, s).await {
                                warn!("Error serving connection: {e:?}");
                            }
                        });
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            drop(listener);
                            info!("Stopping endpoints...");
                            break;
                        }
                    }
                }
            }
        });
        Some(handle)
    }

    fn response(res: StatusCode, body: impl Into<Bytes>) -> ServerResponse {
        Response::builder()
            .status(res)
            .body(Full::new(body.into()))
            .map_err(anyhow::Error::new)
    }

    fn response_with_content_type(
        res: StatusCode,
        content_type: &str,
        body: impl Into<Bytes>,
    ) -> ServerResponse {
        Response::builder()
            .status(res)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(Full::new(body.into()))
            .map_err(anyhow::Error::new)
    }

    fn handle_metrics(&self) -> ServerResponse {
        match &self.metrics {
            Some(metrics) => metrics.encode().map(|buf| {
                Server::response_with_content_type(
                    StatusCode::OK,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    buf,
                )
            })?,
            None => Server::response(StatusCode::SERVICE_UNAVAILABLE, ""),
        }
    }

    fn handle_health_check(&self) -> ServerResponse {
        let res = if self.health_check {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        Server::response(res, "")
    }

    async fn handle_profiler_status(&self) -> ServerResponse {
        let Some(profiler) = &self.profiler else {
            return Server::response(StatusCode::INTERNAL_SERVER_ERROR, "Profiler is not enabled");
        };
        let body = profiler.get_status().await;
        Server::response_with_content_type(StatusCode::OK, "application/json", body)
    }

    async fn handle_cpu_profiler(&self, body: Incoming) -> ServerResponse {
        let Some(profiler) = &self.profiler else {
            return Server::response(StatusCode::INTERNAL_SERVER_ERROR, "Profiler is not enabled");
        };

        let body = match body.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                return Server::response(
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read request body: {e}"),
                )
            }
        };

        if body == "on" {
            match profiler.start().await {
                Ok(_) => Server::response_with_content_type(
                    StatusCode::OK,
                    "text/plain",
                    "CPU profiler starter",
                ),
                Err(e) => Server::response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to start CPU profiler: {e}"),
                ),
            }
        } else if body == "off" {
            match profiler.stop().await {
                Ok(_) => Server::response_with_content_type(
                    StatusCode::OK,
                    "text/plain",
                    "CPU profiler stopped",
                ),
                Err(e) => Server::response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to stop CPU profiler: {e}"),
                ),
            }
        } else {
            Server::response(
                StatusCode::BAD_REQUEST,
                format!("Invalid request body: {body:?}"),
            )
        }
    }

    async fn handle_cpu_report(&self) -> ServerResponse {
        let Some(profiler) = &self.profiler else {
            return Server::response(StatusCode::INTERNAL_SERVER_ERROR, "Profiler is not enabled");
        };

        match profiler.get().await {
            Ok(profile) => {
                Server::response_with_content_type(StatusCode::OK, "text/plain", profile)
            }
            Err(e) => Server::response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get CPU profile: {e}"),
            ),
        }
    }
}

impl Service<Request<Incoming>> for Server {
    type Response = Response<Full<Bytes>>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let s = self.clone();
        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                (&Method::GET, "/metrics") => s.handle_metrics(),
                (&Method::GET, "/health_check") => s.handle_health_check(),
                (&Method::POST, "/profile/cpu") => s.handle_cpu_profiler(req.into_body()).await,
                (&Method::GET, "/profile/cpu") => s.handle_cpu_report().await,
                (&Method::GET, "/profile") => s.handle_profiler_status().await,
                _ => Server::response(StatusCode::NOT_FOUND, ""),
            }
        })
    }
}
