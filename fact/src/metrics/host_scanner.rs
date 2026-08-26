use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelValue, Copy)]
pub enum ScanLabels {
    Scans,
    ElementsScanned,
    InodeRemoved,
    InodeHit,
    DirectoryScanned,
    FileScanned,
    SymlinkScanned,
    FileRemoved,
    FileUpdated,
    FsItemIgnored,
    FsMetadataFailed,
    GlobFailed,
}

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelSet)]
pub struct ScanEvents {
    label: ScanLabels,
}

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelValue, Copy)]
pub enum HostScannerLabels {
    Total,
    Added,
    Dropped,
    Ignored,
    MkDir,
    RmDir,
    Mount,
}

#[derive(Clone, Hash, Eq, Debug, PartialEq, EncodeLabelSet)]
pub struct HostScannerEvents {
    label: HostScannerLabels,
}

#[derive(Debug, Clone)]
/// Metrics for the HostScanner component
pub struct HostScannerMetrics {
    pub events: Family<HostScannerEvents, Counter<u64>>,
    pub scan: Family<ScanEvents, Counter<u64>>,
    pub scan_duration: Histogram,
    pub scan_partial_duration: Histogram,
    pub inode_map_size: Gauge,
}

impl HostScannerMetrics {
    pub(super) fn new() -> Self {
        let events = Family::<HostScannerEvents, Counter<u64>>::default();
        for label in [
            HostScannerLabels::Total,
            HostScannerLabels::Added,
            HostScannerLabels::Dropped,
            HostScannerLabels::Ignored,
            HostScannerLabels::MkDir,
            HostScannerLabels::RmDir,
            HostScannerLabels::Mount,
        ] {
            let _ = events.get_or_create(&HostScannerEvents { label });
        }

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
            ScanLabels::FsMetadataFailed,
            ScanLabels::GlobFailed,
        ] {
            let _ = scan.get_or_create(&ScanEvents { label });
        }
        let scan_duration = Histogram::new([
            0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0,
        ]);
        let scan_partial_duration = Histogram::new([
            0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0,
        ]);

        let inode_map_size = Gauge::default();

        HostScannerMetrics {
            events,
            scan,
            scan_duration,
            scan_partial_duration,
            inode_map_size,
        }
    }

    pub(super) fn register(&self, reg: &mut Registry) {
        reg.register(
            "host_scanner_events",
            "Events processed by the host scanner component",
            self.events.clone(),
        );

        reg.register(
            "host_scanner_scan",
            "Counter of events by scans from the host scanner component",
            self.scan.clone(),
        );

        reg.register(
            "host_scanner_scan_duration",
            "Histogram of scan durations from the host scanner component",
            self.scan_duration.clone(),
        );

        reg.register(
            "host_scanner_scan_partial_duration",
            "Histogram of partial scan durations from the host scanner component",
            self.scan_partial_duration.clone(),
        );

        reg.register(
            "host_scanner_inode_map_size",
            "Gauge tracking the number of elements in the inode map",
            self.inode_map_size.clone(),
        );
    }

    pub fn events_inc(&self, label: HostScannerLabels) {
        self.events
            .get_or_create(&HostScannerEvents { label })
            .inc();
    }

    pub fn scan_inc(&self, label: ScanLabels) {
        self.scan.get_or_create(&ScanEvents { label }).inc();
    }
}
