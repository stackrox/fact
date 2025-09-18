use aya::maps::{MapData, PerCpuArray};
use prometheus_client::registry::Registry;

use fact_ebpf::{metrics_by_hook_t, metrics_t};

use crate::metrics::MetricEvents;

use super::{EventCounter, LabelValues};

pub struct KernelMetrics {
    file_open: EventCounter,
    map: PerCpuArray<MapData, metrics_t>,
}

impl KernelMetrics {
    pub fn new(reg: &mut Registry, kernel_metrics: PerCpuArray<MapData, metrics_t>) -> Self {
        let file_open = EventCounter::new(
            "kernel_file_open_events",
            "Events processed by the file_open LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );

        file_open.register(reg);

        KernelMetrics {
            file_open,
            map: kernel_metrics,
        }
    }

    fn refresh_labels(ec: &EventCounter, m: &metrics_by_hook_t) {
        ec.counter.clear();
        ec.counter
            .get_or_create(&MetricEvents {
                label: LabelValues::Total,
            })
            .inc_by(m.total);

        ec.counter
            .get_or_create(&MetricEvents {
                label: LabelValues::Added,
            })
            .inc_by(m.added);

        ec.counter
            .get_or_create(&MetricEvents {
                label: LabelValues::Error,
            })
            .inc_by(m.error);

        ec.counter
            .get_or_create(&MetricEvents {
                label: LabelValues::Ignored,
            })
            .inc_by(m.ignored);

        ec.counter
            .get_or_create(&MetricEvents {
                label: LabelValues::RingbufferFull,
            })
            .inc_by(m.ringbuffer_full);
    }

    pub fn collect(&self) -> anyhow::Result<()> {
        let metrics = self
            .map
            .get(&0, 0)?
            .iter()
            .fold(metrics_t::default(), |acc, x| acc.accumulate(x));

        KernelMetrics::refresh_labels(&self.file_open, &metrics.file_open);

        Ok(())
    }
}
