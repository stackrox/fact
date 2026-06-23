use aya::maps::{MapData, PerCpuArray};
use prometheus_client::registry::Registry;

use fact_ebpf::{metrics_by_hook_t, metrics_t};

use crate::metrics::MetricEvents;

use super::{EventCounter, LabelValues};

macro_rules! define_kernel_metrics {
    ($($hook:ident),+ $(,)?) => {
        pub struct KernelMetrics {
            $($hook: EventCounter,)+
            map: PerCpuArray<MapData, metrics_t>,
        }

        impl KernelMetrics {
            pub fn new(reg: &mut Registry, kernel_metrics: PerCpuArray<MapData, metrics_t>) -> Self {
                $(
                    let $hook = EventCounter::new(
                        concat!("kernel_", stringify!($hook), "_events"),
                        concat!("Events processed by the ", stringify!($hook), " LSM hook"),
                        &[],
                    );
                    $hook.register(reg);
                )+

                KernelMetrics {
                    $($hook,)+
                    map: kernel_metrics,
                }
            }

            pub fn collect(&self) -> anyhow::Result<()> {
                let metrics = self
                    .map
                    .get(&0, 0)?
                    .iter()
                    .fold(metrics_t::default(), |acc, x| acc.accumulate(x));

                $(Self::refresh_labels(&self.$hook, &metrics.$hook);)+

                Ok(())
            }

            fn refresh_labels(ec: &EventCounter, m: &metrics_by_hook_t) {
                ec.counter.clear();
                for (label, value) in [
                    (LabelValues::Total, m.total),
                    (LabelValues::Added, m.added),
                    (LabelValues::Error, m.error),
                    (LabelValues::Ignored, m.ignored),
                    (LabelValues::RingbufferFull, m.ringbuffer_full),
                ] {
                    ec.counter
                        .get_or_create(&MetricEvents { label })
                        .inc_by(value);
                }
            }
        }
    };
}

define_kernel_metrics!(
    file_open,
    path_unlink,
    path_chmod,
    path_chown,
    path_rename,
    path_mkdir,
    path_rmdir,
    d_instantiate,
    inode_setxattr,
    inode_removexattr,
    inode_set_acl,
);
