from __future__ import annotations

import requests
from prometheus_client import CollectorRegistry
from prometheus_client.metrics_core import Metric
from prometheus_client.openmetrics.exposition import generate_latest
from prometheus_client.openmetrics.parser import (
    text_string_to_metric_families,
)
from prometheus_client.samples import Sample


class MetricsSnapshot:
    """Parsed snapshot of Prometheus metrics from fact's /metrics endpoint.

    Stores the full list of ``Metric`` family objects returned by the
    prometheus-client parser so that snapshots can be diffed and
    serialised back to valid OpenMetrics text exposition format.
    """

    def __init__(self, families: list[Metric]):
        self._families = families
        self._index: dict[str, dict[str, float]] = {}
        for fam in families:
            by_label: dict[str, float] = {}
            for s in fam.samples:
                key = _label_key(s.labels)
                by_label[key] = s.value
            self._index[fam.name] = by_label

    @classmethod
    def from_text(cls, text: str) -> MetricsSnapshot:
        families = list(text_string_to_metric_families(text))
        return cls(families)

    @classmethod
    def fetch(cls, endpoint: str) -> MetricsSnapshot:
        resp = requests.get(f'http://{endpoint}/metrics')
        resp.raise_for_status()
        return cls.from_text(resp.text)

    def get(
        self,
        metric_name: str,
        labels: dict[str, str] | None = None,
    ) -> str | None:
        """Look up a single metric value.

        ``metric_name`` is matched as a substring against family
        names (mirrors the old ``get_metric_value`` behaviour).
        ``labels`` must match exactly when provided.

        Returns the value as a string, or ``None``.
        """
        labels = labels or {}
        key = _label_key(labels)
        for name, by_label in self._index.items():
            if metric_name not in name:
                continue
            if key in by_label:
                return str(int(by_label[key]))
        return None

    def delta(self, after: MetricsSnapshot) -> MetricsSnapshot:
        """Return a new snapshot containing metrics."""
        delta_families: list[Metric] = []
        for fam in after._families:
            before_labels = self._index.get(fam.name, {})
            delta_samples: list[Sample] = []
            for s in fam.samples:
                key = _label_key(s.labels)
                before_val = before_labels.get(key, 0.0)
                d = s.value - before_val
                delta_samples.append(Sample(s.name, s.labels, d, s.timestamp))
            if delta_samples:
                m = Metric(fam.name, fam.documentation, fam.type)
                m.samples = delta_samples
                delta_families.append(m)
        return MetricsSnapshot(delta_families)

    def to_text(self) -> str:
        """Serialise to OpenMetrics text exposition format."""
        registry = CollectorRegistry()
        registry.register(_FamilyCollector(self._families))
        return generate_latest(registry).decode('utf-8')


class _FamilyCollector:
    """Minimal Collector that replays pre-built Metric objects."""

    def __init__(self, families: list[Metric]):
        self._families = families

    def collect(self) -> list[Metric]:
        return self._families

    def describe(self) -> list[Metric]:
        return self._families


def _label_key(labels: dict[str, str]) -> str:
    return ','.join(f'{k}={v}' for k, v in sorted(labels.items()))


def get_metric_value(
    fact_config: tuple[dict, str],
    metric_name: str,
    labels: dict[str, str] | None = None,
) -> str | None:
    """Query Prometheus metrics endpoint to get the value of a metric.

    Args:
        fact_config: The fact configuration tuple
            (config dict, config file path).
        metric_name: Name of the metric to query
            (e.g., "host_scanner_scan").
        labels: Optional dict of label filters
            (e.g., {"label": "InodeRemoved"}).

    Returns:
        The metric value as a string if found, None otherwise.
    """
    config, _ = fact_config
    snapshot = MetricsSnapshot.fetch(config['endpoint']['address'])
    return snapshot.get(metric_name, labels)
