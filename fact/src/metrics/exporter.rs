use std::{net::SocketAddr, sync::Arc};

use aya::maps::{MapData, PerCpuArray};
use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::{net::TcpListener, pin, sync::watch};

use fact_ebpf::metrics_t;

use super::{kernel_metrics::KernelMetrics, Metrics};

pub struct Exporter {
    registry: Arc<Registry>,
    pub metrics: Arc<Metrics>,
    kernel_metrics: Arc<KernelMetrics>,
}

impl Exporter {
    pub fn new(kernel_metrics: PerCpuArray<MapData, metrics_t>) -> Self {
        let mut registry = Registry::with_prefix("stackrox_fact");
        let metrics = Arc::new(Metrics::new(&mut registry));
        let kernel_metrics = Arc::new(KernelMetrics::new(&mut registry, kernel_metrics));
        let registry = Arc::new(registry);
        Exporter {
            registry,
            metrics,
            kernel_metrics,
        }
    }

    pub fn start(&self, running: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        info!("Starting metrics server");

        let registry = self.registry.clone();
        let kernel_metrics = self.kernel_metrics.clone();
        tokio::spawn(async move {
            // TODO ROX-30811: Make socket and address configurable
            let addr = SocketAddr::from(([0, 0, 0, 0], 9001));
            let tcp_listener = TcpListener::bind(addr).await.unwrap();
            let server = http1::Builder::new();

            while let Ok((stream, _)) = tcp_listener.accept().await {
                let io = TokioIo::new(stream);
                let s = server.clone();
                let mut r = running.clone();
                let registry = registry.clone();
                let km = kernel_metrics.clone();

                tokio::spawn(async move {
                    let conn = s.serve_connection(io, service_fn(|_| {
                        let registry = registry.clone();
                        let km = km.clone();

                        async move {
                            let mut buf = String::new();
                            if let Err(e) = km.collect() {
                                warn!("Failed to collect kernel metrics: {e}");
                            }
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
