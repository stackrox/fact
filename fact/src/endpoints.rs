use std::{future::Future, pin::Pin};

use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

use crate::{config::EndpointConfig, metrics::exporter::Exporter};

#[derive(Clone)]
pub struct Server {
    metrics: Exporter,
    config: watch::Receiver<EndpointConfig>,
    running: watch::Receiver<bool>,
}

impl Server {
    pub fn new(
        metrics: Exporter,
        config: watch::Receiver<EndpointConfig>,
        running: watch::Receiver<bool>,
    ) -> Self {
        Server {
            metrics,
            config,
            running,
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
                    Ok(running) => {
                        if running {
                            info!("Reloading endpoints...");
                        } else {
                            info!("Stopping endpoints...");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("endpoints error: {e}");
                    }
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
        config.health_check() || config.expose_metrics()
    }

    fn health_check_is_active(&self) -> bool {
        self.config.borrow().health_check()
    }

    fn metrics_is_active(&self) -> bool {
        self.config.borrow().expose_metrics()
    }

    fn make_response(
        res: StatusCode,
        body: String,
    ) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        Ok(Response::builder()
            .status(res)
            .body(Full::new(Bytes::from(body)))
            .unwrap())
    }

    fn handle_metrics(&self) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        if !self.metrics_is_active() {
            return Server::make_response(StatusCode::SERVICE_UNAVAILABLE, String::new());
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
        Server::make_response(res, String::new())
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
                _ => Server::make_response(StatusCode::NOT_FOUND, String::new()),
            }
        })
    }
}
