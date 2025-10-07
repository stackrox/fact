use std::sync::Arc;

use aya::maps::{MapData, PerCpuArray};
use log::warn;
use prometheus_client::{encoding::text::encode, registry::Registry};

use fact_ebpf::metrics_t;

use super::{kernel_metrics::KernelMetrics, Metrics};

#[derive(Clone)]
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

    pub fn encode(&self) -> anyhow::Result<String> {
        let mut buf = String::new();
        if let Err(e) = self.kernel_metrics.collect() {
            warn!("Failed to collect kernel metrics: {e}");
        }
        encode(&mut buf, &self.registry)?;
        Ok(buf)
    }
}
