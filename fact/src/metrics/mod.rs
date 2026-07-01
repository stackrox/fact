use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};

use host_scanner::HostScannerMetrics;

pub mod exporter;
pub mod host_scanner;
mod kernel_metrics;

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelValue, Copy)]
enum LabelValues {
    Total,
    Added,
    Dropped,
    Ignored,
    Error,
    RingbufferFull,
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

    fn register(&self, reg: &mut Registry) {
        reg.register(self.name, self.help, self.counter.clone());
    }

    fn inc_label(&self, label: LabelValues) {
        self.counter
            .get(&MetricEvents { label })
            .expect("label not found")
            .inc();
    }

    fn inc_label_by(&self, label: LabelValues, n: u64) {
        self.counter
            .get(&MetricEvents { label })
            .expect("label not found")
            .inc_by(n);
    }

    pub fn added(&self) {
        self.inc_label(LabelValues::Added);
    }

    pub fn dropped(&self) {
        self.inc_label(LabelValues::Dropped);
    }

    pub fn dropped_n(&self, n: u64) {
        self.inc_label_by(LabelValues::Dropped, n);
    }

    pub fn ignored(&self) {
        self.inc_label(LabelValues::Ignored);
    }

    pub fn errored(&self) {
        self.inc_label(LabelValues::Error);
    }
}

#[derive(Debug, Clone)]
/// Metrics for the output component
pub struct OutputMetrics {
    pub stdout: EventCounter,
    pub grpc: EventCounter,
    pub otel: EventCounter,
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
        let otel_counter = EventCounter::new(
            "output_otel_events",
            "Events processed by the otel output component",
            &labels,
        );

        OutputMetrics {
            stdout: stdout_counter,
            grpc: grpc_counter,
            otel: otel_counter,
        }
    }

    fn register(&self, reg: &mut Registry) {
        self.stdout.register(reg);
        self.grpc.register(reg);
        self.otel.register(reg);
    }
}

pub struct Metrics {
    pub bpf_worker: EventCounter,
    pub rate_limiter: EventCounter,
    pub output: OutputMetrics,
    pub host_scanner: HostScannerMetrics,
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

        let rate_limiter = EventCounter::new(
            "rate_limiter_events",
            "Events processed by the rate limiter",
            &[LabelValues::Added, LabelValues::Dropped, LabelValues::Error],
        );
        rate_limiter.register(registry);

        let output_metrics = OutputMetrics::new();
        output_metrics.register(registry);

        let host_scanner = HostScannerMetrics::new();
        host_scanner.register(registry);

        Metrics {
            bpf_worker,
            rate_limiter,
            output: output_metrics,
            host_scanner,
        }
    }
}
