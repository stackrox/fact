import requests
from prometheus_client.parser import text_string_to_metric_families


class MetricsSnapshot:
    """
    A parsed snapshot of Prometheus/OpenMetrics metrics.

    Supports querying by metric name and labels:

        ss = metrics.snapshot()
        assert ss.get("rate_limiter_events", label="Dropped") == 5
        assert ss.get("bpf_events", label="Added") > 0

    Metric names are matched without the "stackrox_fact_" prefix and
    "_total" counter suffix, so "rate_limiter_events" matches
    "stackrox_fact_rate_limiter_events_total".
    """

    _PREFIX = "stackrox_fact_"
    _TOTAL_SUFFIX = "_total"

    def __init__(self, text):
        self._entries = []
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                self._entries.append((sample.name, sample.labels, sample.value))

    @classmethod
    def _normalize(cls, name):
        return name.removeprefix(cls._PREFIX).removesuffix(cls._TOTAL_SUFFIX)

    def get(self, metric, **labels):
        """
        Get the value of a metric, optionally filtered by labels.

        Args:
            metric: Metric name, with or without the "stackrox_fact_"
                prefix and "_total" suffix.
            **labels: Label key=value pairs to match.

        Returns:
            The metric value as int or float.

        Raises:
            KeyError: If no matching metric is found.
            ValueError: If multiple metrics match.
        """
        target = self._normalize(metric)
        matches = []
        for name, entry_labels, value in self._entries:
            if self._normalize(name) != target:
                continue
            if all(entry_labels.get(k) == v for k, v in labels.items()):
                matches.append(value)

        if not matches:
            label_desc = ', '.join(f'{k}="{v}"' for k, v in labels.items())
            key = f'{metric}{{{label_desc}}}' if label_desc else metric
            available = '\n  '.join(
                f'{n} {ls} = {v}' for n, ls, v in self._entries
            )
            raise KeyError(
                f'metric {key!r} not found. Available:\n  {available}'
            )
        if len(matches) > 1:
            raise ValueError(
                f'{metric} matched {len(matches)} entries; use labels to '
                f'narrow the result'
            )
        return matches[0]

    def get_all(self, metric, **labels):
        """Like get(), but returns a list of all matching values."""
        target = self._normalize(metric)
        return [
            value for name, entry_labels, value in self._entries
            if self._normalize(name) == target
            and all(entry_labels.get(k) == v for k, v in labels.items())
        ]


class MetricsClient:
    """Fetches metrics snapshots from a FACT endpoint."""

    def __init__(self, address):
        self._url = f'http://{address}/metrics'

    def snapshot(self, timeout=30):
        resp = requests.get(self._url, timeout=timeout)
        resp.raise_for_status()
        return MetricsSnapshot(resp.text)
