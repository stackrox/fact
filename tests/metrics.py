import re

import requests


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
    _LINE_RE = re.compile(
        r'^(?P<name>\S+?)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)$'
    )
    _LABEL_RE = re.compile(r'(\w+)="([^"]*)"')

    def __init__(self, text):
        self._entries = []
        for line in text.splitlines():
            if line.startswith('#') or not line.strip():
                continue

            m = self._LINE_RE.match(line)
            if not m:
                continue

            name, raw, labels = m.group('name', 'value', 'labels')

            value = float(raw) if '.' in raw else int(raw)
            labels = dict(self._LABEL_RE.findall(labels or ''))

            self._entries.append((name, labels, value))

    @classmethod
    def _normalize(cls, name):
        if name.startswith(cls._PREFIX):
            name = name[len(cls._PREFIX):]
        if name.endswith(cls._TOTAL_SUFFIX):
            name = name[:-len(cls._TOTAL_SUFFIX)]
        return name

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
