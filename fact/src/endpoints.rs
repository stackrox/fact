use std::{future::Future, net::SocketAddr, pin::Pin};

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

use crate::metrics::exporter::Exporter;

#[derive(Clone)]
pub struct Server {
    metrics: Option<Exporter>,
    health_check: bool,
}

impl Server {
    pub fn new(metrics: Exporter, expose_metrics: bool, health_check: bool) -> Self {
        let metrics = if expose_metrics { Some(metrics) } else { None };
        Server {
            metrics,
            health_check,
        }
    }

    pub fn start(self, mut running: watch::Receiver<bool>) -> Option<JoinHandle<()>> {
        // If there is nothing to expose, we don't run the hyper server
        if self.metrics.is_none() && !self.health_check {
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
        match &self.metrics {
            Some(metrics) => metrics.encode().map(|buf| {
                let body = Full::new(Bytes::from(buf));
                Response::builder()
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "application/openmetrics-text; version=1.0.0; charset=utf-8",
                    )
                    .body(body)
                    .map_err(anyhow::Error::new)
            })?,
            None => Server::make_response(StatusCode::SERVICE_UNAVAILABLE, String::new()),
        }
    }

    fn handle_health_check(&self) -> Result<Response<Full<Bytes>>, anyhow::Error> {
        let res = if self.health_check {
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
