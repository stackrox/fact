use std::{net::SocketAddr, sync::Arc};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use log::info;
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::{net::TcpListener, pin, sync::watch};

use super::Metrics;

pub struct Exporter {
    registry: Arc<Registry>,
    pub metrics: Arc<Metrics>,
}

impl Exporter {
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("stackrox_fact");
        let metrics = Arc::new(Metrics::new(&mut registry));
        let registry = Arc::new(registry);
        Exporter { registry, metrics }
    }

    pub fn start(&self, running: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        info!("Starting metrics server");

        let registry = self.registry.clone();
        tokio::spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], 9001));
            let tcp_listener = TcpListener::bind(addr).await.unwrap();
            let server = http1::Builder::new();

            while let Ok((stream, _)) = tcp_listener.accept().await {
                let io = TokioIo::new(stream);
                let s = server.clone();
                let mut r = running.clone();
                let registry = registry.clone();

                tokio::spawn(async move {
                    let conn = s.serve_connection(io, service_fn(|_| {
                        let registry = registry.clone();

                        async move {
                            let mut buf = String::new();
                            encode(&mut buf, &registry).map_err(std::io::Error::other).map(|_| {
                                let body = Full::new(Bytes::from(buf));
                                Response::builder()
                                    .header(hyper::header::CONTENT_TYPE, "application/openmetrics-text; version=1.0.0; charset=utf-8")
                                    .body(body)
                                    .unwrap()
                            })
                        }}));

                    pin!(conn);
                    tokio::select! {
                        _ = conn.as_mut() => {},
                        _ = r.changed() => {
                            if !*r.borrow() {
                                info!("Interrupted metrics query");
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        })
    }
}
