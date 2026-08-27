use std::{future::Future, pin::Pin};

use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::{
    config::EndpointConfig,
    host_scanner::{self, IntrospectionRequestType as HostScannerReq},
    metrics::exporter::Exporter,
};

#[derive(Clone)]
pub struct Server {
    metrics: Exporter,
    config: watch::Receiver<EndpointConfig>,
    running: watch::Receiver<bool>,

    host_scanner_intro: mpsc::Sender<host_scanner::IntrospectionRequest>,
}

impl Server {
    pub fn new(
        metrics: Exporter,
        config: watch::Receiver<EndpointConfig>,
        running: watch::Receiver<bool>,
        host_scanner_intro: mpsc::Sender<host_scanner::IntrospectionRequest>,
    ) -> Self {
        Server {
            metrics,
            config,
            running,
            host_scanner_intro,
        }
    }

    /// Consume the Server into a task that will serve the endpoints.
    ///
    /// If all endpoints are disabled, no port will be listened on and
    /// the task goes into an idle state waiting for configuration
    /// changes.
    pub fn start(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let res = if self.is_active() {
                    self.serve().await
                } else {
                    self.idle().await
                };

                match res {
                    Ok(true) => info!("Reloading endpoints..."),
                    Ok(false) => {
                        info!("Stopping endpoints...");
                        break;
                    }
                    Err(e) => warn!("endpoints error: {e}"),
                };
            }
        })
    }

    /// Wait for configuration changes or fact to stop.
    async fn idle(&mut self) -> anyhow::Result<bool> {
        tokio::select! {
            _ = self.config.changed() => Ok(true),
            _ = self.running.changed() => Ok(*self.running.borrow()),
        }
    }

    /// Serve requests on the configured endpoints.
    ///
    /// If a configuration change is detected, returning from this
    /// method will handle reloading it.
    async fn serve(&mut self) -> anyhow::Result<bool> {
        let addr = self.config.borrow().address();
        let listener = TcpListener::bind(addr).await?;

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
                _ = self.config.changed() => return Ok(true),
                _ = self.running.changed() => return Ok(*self.running.borrow()),
            }
        }
    }

    /// Check if there are active endpoints to serve.
    fn is_active(&self) -> bool {
        let config = self.config.borrow();
        config.health_check() || config.expose_metrics() || config.introspection()
    }

    fn health_check_is_active(&self) -> bool {
        self.config.borrow().health_check()
    }

    fn metrics_is_active(&self) -> bool {
        self.config.borrow().expose_metrics()
    }

    fn make_response(
        res: StatusCode,
        body: impl Into<Bytes>,
    ) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        Ok(Response::builder()
            .status(res)
            .body(Full::new(body.into()))
            .unwrap())
    }

    async fn handle_metrics(&self) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        if !self.metrics_is_active() {
            return Server::make_response(StatusCode::SERVICE_UNAVAILABLE, "");
        }

        // Trigger an update of the inode_map_size metric
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .host_scanner_intro
            .send((HostScannerReq::InodeMapSize, tx))
            .await
        {
            return Server::make_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to request update inode_map_size metric: {e:?}"),
            );
        }
        if let Err(e) = rx.await {
            return Server::make_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update inode_map_size metric: {e:?}"),
            );
        }
        self.metrics.encode().map(|buf| {
            let body = Full::new(Bytes::from(buf));
            Response::builder()
                .header(
                    hyper::header::CONTENT_TYPE,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )
                .body(body)
                .map_err(anyhow::Error::new)
        })?
    }

    fn handle_health_check(&self) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        let res = if self.health_check_is_active() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        Server::make_response(res, "")
    }

    async fn handle_inodes(&self) -> anyhow::Result<Response<Full<Bytes>>> {
        if !self.config.borrow().introspection() {
            return Server::make_response(StatusCode::SERVICE_UNAVAILABLE, "");
        }

        let (tx, rx) = oneshot::channel();
        if let Err(e) = self
            .host_scanner_intro
            .send((HostScannerReq::InodeMap, tx))
            .await
        {
            return Server::make_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        let res = match rx.await {
            Ok(res) => res,
            Err(e) => {
                return Server::make_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
            }
        };

        use host_scanner::IntrospectionResponseType::*;
        match res {
            InodeMap(Ok(b)) => Response::builder()
                .header(
                    hyper::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .body(Full::new(Bytes::from(b)))
                .map_err(anyhow::Error::new),
            InodeMap(Err(e)) => {
                Server::make_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            InodeMapSize => unreachable!("received InodeMapSize response to InodeMap request"),
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
                (&Method::GET, "/metrics") => s.handle_metrics().await,
                (&Method::GET, "/health_check") => s.handle_health_check(),
                (&Method::GET, "/inodes") => s.handle_inodes().await,
                _ => Server::make_response(StatusCode::NOT_FOUND, ""),
            }
        })
    }
}
