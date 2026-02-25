use aya::maps::{MapData, PerCpuArray};
use prometheus_client::registry::Registry;

use fact_ebpf::{metrics_by_hook_t, metrics_t};

use crate::metrics::MetricEvents;

use super::{EventCounter, LabelValues};

pub struct KernelMetrics {
    file_open: EventCounter,
    path_unlink: EventCounter,
    path_chmod: EventCounter,
    path_chown: EventCounter,
    path_rename: EventCounter,
    map: PerCpuArray<MapData, metrics_t>,
}

impl KernelMetrics {
    pub fn new(reg: &mut Registry, kernel_metrics: PerCpuArray<MapData, metrics_t>) -> Self {
        let file_open = EventCounter::new(
            "kernel_file_open_events",
            "Events processed by the file_open LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );
        let path_unlink = EventCounter::new(
            "kernel_path_unlink_events",
            "Events processed by the path_unlink LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );
        let path_chmod = EventCounter::new(
            "kernel_path_chmod_events",
            "Events processed by the path_chmod LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );
        let path_chown = EventCounter::new(
            "kernel_path_chown_events",
            "Events processed by the path_chown LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );
        let path_rename = EventCounter::new(
            "kernel_path_rename_events",
            "Events processed by the path_rename LSM hook",
            &[], // Labels are not needed since `collect` will add them all
        );

        file_open.register(reg);
        path_unlink.register(reg);
        path_chmod.register(reg);
        path_chown.register(reg);
        path_rename.register(reg);

        KernelMetrics {
            file_open,
            path_unlink,
            path_chmod,
            path_chown,
            path_rename,
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
        KernelMetrics::refresh_labels(&self.path_unlink, &metrics.path_unlink);
        KernelMetrics::refresh_labels(&self.path_chmod, &metrics.path_chmod);
        KernelMetrics::refresh_labels(&self.path_chown, &metrics.path_chown);
        KernelMetrics::refresh_labels(&self.path_rename, &metrics.path_rename);

        Ok(())
    }
}
