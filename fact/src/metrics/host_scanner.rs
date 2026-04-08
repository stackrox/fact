use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};

use crate::metrics::{EventCounter, LabelValues as EventLabels};

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelValue, Copy)]
pub enum ScanLabels {
    Scans,
    ElementsScanned,
    InodeRemoved,
    InodeHit,
    DirectoryScanned,
    FileScanned,
    FileRemoved,
    FileUpdated,
    FsItemIgnored,
}

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelSet)]
pub struct ScanEvents {
    label: ScanLabels,
}

#[derive(Debug, Clone)]
/// Metrics for the HostScanner component
pub struct HostScannerMetrics {
    pub events: EventCounter,
    pub scan: Family<ScanEvents, Counter<u64>>,
}

impl HostScannerMetrics {
    pub(super) fn new() -> Self {
        let labels = [
            EventLabels::Total,
            EventLabels::Added,
            EventLabels::Dropped,
            EventLabels::Ignored,
        ];
        let events = EventCounter::new(
            "host_scanner_events",
            "Events processed by the host scanner component",
            &labels,
        );

        let scan: Family<ScanEvents, Counter<u64>> = Default::default();
        for label in [
            ScanLabels::Scans,
            ScanLabels::ElementsScanned,
            ScanLabels::InodeRemoved,
            ScanLabels::InodeHit,
            ScanLabels::DirectoryScanned,
            ScanLabels::FileScanned,
            ScanLabels::FileRemoved,
            ScanLabels::FileUpdated,
            ScanLabels::FsItemIgnored,
        ] {
            let _ = scan.get_or_create(&ScanEvents { label });
        }

        HostScannerMetrics { events, scan }
    }

    pub(super) fn register(&self, reg: &mut Registry) {
        self.events.register(reg);
        reg.register(
            "host_scanner_scan",
            "Counter of events by scans from the host scanner component",
            self.scan.clone(),
        );
    }

    pub fn scan_inc(&self, label: ScanLabels) {
        self.scan.get_or_create(&ScanEvents { label }).inc();
    }
}
