use aya::maps::{MapData, PerCpuArray};
use prometheus_client::registry::Registry;

use crate::bpf::bindings::{metrics_by_type_t, metrics_t};

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
            &[
                LabelValues::Added,
                LabelValues::Ignored,
                LabelValues::Dropped,
            ],
        );

        file_open.register(reg);

        KernelMetrics {
            file_open,
            map: kernel_metrics,
        }
    }

    pub fn collect(&self) -> anyhow::Result<()> {
        let metrics = self.map.get(&0, 0)?.iter().fold(
            metrics_t {
                file_open: metrics_by_type_t {
                    total: 0,
                    added: 0,
                    dropped: 0,
                    ignored: 0,
                },
            },
            |acc, x| acc.accumulate(x),
        );

        self.file_open.counter.clear();
        self.file_open
            .counter
            .get_or_create(&super::MetricEvents {
                label: LabelValues::Added,
            })
            .inc_by(metrics.file_open.added);

        self.file_open
            .counter
            .get_or_create(&super::MetricEvents {
                label: LabelValues::Ignored,
            })
            .inc_by(metrics.file_open.ignored);

        self.file_open
            .counter
            .get_or_create(&super::MetricEvents {
                label: LabelValues::Dropped,
            })
            .inc_by(metrics.file_open.dropped);

        self.file_open
            .counter
            .get_or_create(&super::MetricEvents {
                label: LabelValues::Total,
            })
            .inc_by(metrics.file_open.total);

        Ok(())
    }
}
