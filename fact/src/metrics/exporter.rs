use std::sync::Arc;

use log::warn;
use prometheus_client::{encoding::text::encode, registry::Registry};

use super::{Metrics, kernel_metrics::KernelMetrics};

#[derive(Clone)]
pub struct Exporter {
    registry: Arc<Registry>,
    kernel_metrics: Option<Arc<KernelMetrics>>,
}

impl Exporter {
    pub fn new(metrics_user: &Metrics, metrics_kernel: Option<KernelMetrics>) -> Self {
        let mut registry = Registry::with_prefix("stackrox_fact");
        metrics_user.register(&mut registry);
        if let Some(metrics_kernel) = &metrics_kernel {
            metrics_kernel.register(&mut registry);
        }
        let kernel_metrics = metrics_kernel.map(Arc::new);
        let registry = Arc::new(registry);
        Exporter {
            registry,
            kernel_metrics,
        }
    }

    pub fn encode(&self) -> anyhow::Result<String> {
        let mut buf = String::new();
        if let Some(ref km) = self.kernel_metrics
            && let Err(e) = km.collect()
        {
            warn!("Failed to collect kernel metrics: {e}");
        }
        encode(&mut buf, &self.registry)?;
        Ok(buf)
    }
}
