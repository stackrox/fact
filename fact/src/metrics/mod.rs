use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};

pub mod exporter;

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelValue, Copy)]
enum LabelValues {
    Added,
    Dropped,
    Ignored,
}

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelSet)]
struct MetricEvents {
    label: LabelValues,
}

#[derive(Debug, Clone)]
/// An abstraction over Family<MetricEvents, Counter<u64>> for easily
/// creating event counters.
pub struct EventCounter {
    counter: Family<MetricEvents, Counter<u64>>,
    name: &'static str,
    help: &'static str,
}

impl EventCounter {
    /// Create a new EventCounter.
    ///
    /// # Arguments
    ///
    /// * `name` - A string to be used as the prometheus name of the metric.
    /// * `help` - A string with the description of what the metric captures.
    /// * `labels` - A list of labels that will be used with the event counter.
    fn new(name: &'static str, help: &'static str, labels: &[LabelValues]) -> Self {
        let counter: Family<MetricEvents, Counter<u64>> = Default::default();

        // Initialize all labels to 0.
        for label in labels {
            let _ = counter.get_or_create(&MetricEvents { label: *label });
        }

        EventCounter {
            counter,
            name,
            help,
        }
    }

    /// Register the counter in the given registry.
    ///
    /// # Arguments
    ///
    /// * `reg` - A prometheus Registry that the counter will be registered into.
    fn register(&self, reg: &mut Registry) {
        reg.register(self.name, self.help, self.counter.clone());
    }

    /// Increment the counter for the Added label.
    ///
    /// Panics if the counter did not add the Added label as part of its
    /// creation step.
    pub fn added(&self) {
        self.counter
            .get(&MetricEvents {
                label: LabelValues::Added,
            })
            .unwrap()
            .inc();
    }

    /// Increment the counter for the Dropped label.
    ///
    /// Panics if the counter did not add the Dropped label as part of
    /// its creation step.
    pub fn dropped(&self) {
        self.counter
            .get(&MetricEvents {
                label: LabelValues::Dropped,
            })
            .unwrap()
            .inc();
    }

    /// Increment the counter for the Ignored label.
    ///
    /// Panics if the counter did not add the Ignored label as part of
    /// its creation step.
    pub fn ignored(&self) {
        self.counter
            .get(&MetricEvents {
                label: LabelValues::Ignored,
            })
            .unwrap()
            .inc();
    }
}

#[derive(Debug, Clone)]
/// Metrics for the output component
pub struct OutputMetrics {
    pub stdout: EventCounter,
    pub grpc: EventCounter,
}

impl OutputMetrics {
    fn new() -> Self {
        let labels = [LabelValues::Added, LabelValues::Dropped];
        let stdout_counter = EventCounter::new(
            "output_stdout_events",
            "Events processed by the stdout output component",
            &labels,
        );
        let grpc_counter = EventCounter::new(
            "output_grpc_events",
            "Events processed by the grpc output component",
            &labels,
        );

        OutputMetrics {
            stdout: stdout_counter,
            grpc: grpc_counter,
        }
    }

    fn register(&self, reg: &mut Registry) {
        self.stdout.register(reg);
        self.grpc.register(reg);
    }
}

pub struct Metrics {
    pub bpf_worker: EventCounter,
    pub output: OutputMetrics,
}

impl Metrics {
    fn new(registry: &mut Registry) -> Self {
        let bpf_worker = EventCounter::new(
            "bpf_events",
            "Events processed by the BPF worker",
            &[
                LabelValues::Added,
                LabelValues::Dropped,
                LabelValues::Ignored,
            ],
        );
        bpf_worker.register(registry);

        let output_metrics = OutputMetrics::new();
        output_metrics.register(registry);

        Metrics {
            bpf_worker,
            output: output_metrics,
        }
    }
}
