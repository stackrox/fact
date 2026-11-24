#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["opensearch-py>=2.7,<4"]
# ///
"""Compare perf-test results for one tag against recent non-tag runs.

Usage:
  ./query.py <tag> [--days 30] [--index fact] [--local data]

<tag> is the `version` stored in OpenSearch (the image tag from CI).

Environment:
  K6_ELASTICSEARCH_URL, K6_ELASTICSEARCH_USER, K6_ELASTICSEARCH_PASSWORD
"""

import argparse
import glob
import json
import math
import os
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch  # type: ignore[import-not-found]

PREFERRED_METRICS = (
    "user_space_cpu",
    "user_space_mem",
    "kernel_space_cpu",
    "kernel_space_mem",
)
PREFERRED_WORKLOADS = ("ignored_and_monitored", "monitored", "ignored")
UNIT_SUFFIXES = (", 90p, median", ", median", ", 90p")
KIND_ORDER = {"scalar": 0, "p50": 1, "p90": 2}


def search(client, index, query, size=10000):
    body = {
        "size": size,
        "_source": ["version", "metric", "workload", "value", "unit"],
        "query": query,
    }
    try:
        hits = client.search(index=index, body=body)["hits"]["hits"]
    except Exception as exc:
        raise SystemExit(f"search failed for index {index}: {exc}") from exc
    return [hit["_source"] for hit in hits]


def percentile(values, percent):
    values = sorted(values)
    position = (len(values) - 1) * percent / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[int(position)]
    return values[lower] * (upper - position) + values[upper] * (position - lower)


def load_local(path):
    docs = []
    for filename in sorted(glob.glob(os.path.join(path, "*.json"))):
        with open(filename, encoding="utf-8") as handle:
            for doc in json.load(handle):
                if isinstance(doc.get("value"), list):
                    for percent, kind in ((90, "90p"), (50, "median")):
                        item = dict(doc)
                        item["value"] = percentile(doc["value"], percent)
                        item["unit"] = f"{doc['unit']}, {kind}"
                        docs.append(item)
                else:
                    docs.append(doc)
    return docs


def base_unit(unit):
    for suffix in UNIT_SUFFIXES:
        if unit.endswith(suffix):
            return unit[: -len(suffix)]
    return unit


@dataclass(frozen=True)
class Stats:
    count: int
    median: float
    minimum: float
    maximum: float
    unit: str


@dataclass(frozen=True)
class Comparison:
    metric: str
    workload: str
    kind: str
    baseline: Stats
    candidate: Stats
    delta_pct: float


def summarize(docs):
    grouped = defaultdict(list)
    units = {}
    for doc in docs:
        unit = doc.get("unit", "")
        kind = (
            "p50"
            if unit.endswith("median")
            else "p90"
            if unit.endswith("90p")
            else "scalar"
        )
        key = (doc["metric"], doc["workload"], kind)
        try:
            grouped[key].append(float(doc["value"]))
        except (KeyError, TypeError, ValueError):
            continue
        units[key] = base_unit(unit)
    return {
        key: Stats(
            count=len(values),
            median=statistics.median(values),
            minimum=min(values),
            maximum=max(values),
            unit=units[key],
        )
        for key, values in grouped.items()
    }


def compare(candidate, baseline):
    rows = []
    for key in sorted(candidate):
        base = baseline.get(key)
        cand = candidate[key]
        if base is None or base.median == 0:
            continue
        rows.append(
            Comparison(
                metric=key[0],
                workload=key[1],
                kind=key[2],
                baseline=base,
                candidate=cand,
                delta_pct=(cand.median - base.median) / base.median * 100,
            )
        )
    return rows


def number(value):
    magnitude = abs(value)
    if magnitude >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f}G"
    if magnitude >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if magnitude >= 1_000:
        return f"{value / 1_000:.2f}k"
    return f"{value:.4g}"


def in_baseline_range(row):
    return row.baseline.minimum <= row.candidate.median <= row.baseline.maximum


def stat_cell(stats):
    return f"{number(stats.median)} ({number(stats.minimum)}-{number(stats.maximum)}, n={stats.count})"


def candidate_cell(row):
    return (
        stat_cell(row.candidate)
        if row.candidate.count > 1
        else number(row.candidate.median)
    )


def candidate_change_cell(row, emphasize):
    candidate = candidate_cell(row)
    if in_baseline_range(row):
        return f"{candidate} (within noise)"
    change = f"{row.delta_pct:+.1f}%"
    return f"{candidate} (**{change}**)" if emphasize else f"{candidate} ({change})"


def ordered(value, preferred):
    return (preferred.index(value) if value in preferred else len(preferred), value)


def metric_section(metric, metric_rows):
    unit = metric_rows[0].baseline.unit
    heading = f"#### `{metric}`" + (f" ({unit})" if unit else "")
    lines = ["", heading]

    by_workload = defaultdict(dict)
    for row in metric_rows:
        by_workload[row.workload][row.kind] = row
    workloads = sorted(by_workload, key=lambda name: ordered(name, PREFERRED_WORKLOADS))
    kinds = sorted(
        {row.kind for row in metric_rows}, key=lambda kind: KIND_ORDER.get(kind, 99)
    )
    emphasize = not metric.startswith("kernel_")

    if kinds == ["scalar"]:
        lines += [
            "",
            "| Workload | Baseline (min-max, n) | Candidate (change) |",
            "| --- | ---: | ---: |",
        ]
        for workload in workloads:
            row = by_workload[workload]["scalar"]
            lines.append(
                f"| {workload} | {stat_cell(row.baseline)} | "
                f"{candidate_change_cell(row, emphasize)} |"
            )
    else:
        lines += [
            "",
            "| Workload | "
            + " | ".join(
                f"{kind} baseline | {kind} candidate (change)" for kind in kinds
            )
            + " |",
            "| --- | " + " | ".join("---: | ---:" for _ in kinds) + " |",
        ]
        for workload in workloads:
            cells = [workload]
            for kind in kinds:
                row = by_workload[workload].get(kind)
                if row is None:
                    cells += ["-", "-"]
                else:
                    cells += [
                        stat_cell(row.baseline),
                        candidate_change_cell(row, emphasize),
                    ]
            lines.append("| " + " | ".join(cells) + " |")
    return lines


def format_markdown(tag, source, candidate_count, baseline, versions, days, rows):
    lines = [
        f"### Performance comparison: `{tag}`",
        "",
        f"Candidate: {candidate_count} docs from `{source}` (one run). "
        f"Baseline: {len(baseline)} docs from {versions} versions (last {days} days).",
    ]

    by_metric = defaultdict(list)
    for row in rows:
        by_metric[row.metric].append(row)

    user_sections = []
    kernel_sections = []
    for metric in sorted(by_metric, key=lambda name: ordered(name, PREFERRED_METRICS)):
        section = metric_section(metric, by_metric[metric])
        if metric.startswith("kernel_"):
            kernel_sections += section
        else:
            user_sections += section

    lines += user_sections
    if kernel_sections:
        lines += [
            "",
            "<details>",
            "<summary>Kernel metrics (informational; noisy)</summary>",
        ]
        lines += kernel_sections
        lines += ["", "</details>"]

    lines += [
        "",
        "Baseline cells are median (min-max, n runs). **Bold** changes fall outside "
        "the baseline range; `within noise` means the candidate is inside it. "
        "`user_space_cpu` is a single perf-stat scalar per run; p50/p90 apply to "
        "sampled metrics.",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="version/tag to compare")
    parser.add_argument(
        "--days", type=int, default=30, help="baseline window (default: 30)"
    )
    parser.add_argument(
        "--index", default="fact", help="OpenSearch index (default: fact)"
    )
    parser.add_argument(
        "--local",
        help="read candidate results from this directory instead of OpenSearch",
    )
    args = parser.parse_args()

    host = os.getenv("K6_ELASTICSEARCH_URL", "")
    host = host.removeprefix("https://").removeprefix("http://").rstrip("/")
    user = os.getenv("K6_ELASTICSEARCH_USER")
    password = os.getenv("K6_ELASTICSEARCH_PASSWORD")
    if not (host and user and password):
        raise SystemExit(
            "set K6_ELASTICSEARCH_URL, K6_ELASTICSEARCH_USER and K6_ELASTICSEARCH_PASSWORD"
        )

    client = OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=(user, password),
        http_compress=True,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=60,
    )

    since = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
    if args.local:
        candidate = load_local(args.local)
    else:
        candidate = search(client, args.index, {"term": {"version.keyword": args.tag}})
    if not candidate:
        raise SystemExit(f"no candidate documents for tag {args.tag!r}")
    baseline = search(
        client,
        args.index,
        {
            "bool": {
                "filter": {"range": {"timestamp": {"gte": since}}},
                "must_not": {"term": {"version.keyword": args.tag}},
            }
        },
    )
    if not baseline:
        raise SystemExit(f"no baseline documents in the last {args.days} days")

    rows = compare(summarize(candidate), summarize(baseline))
    versions = len({doc["version"] for doc in baseline})
    source = args.local or args.index
    print(
        format_markdown(
            args.tag,
            source,
            len(candidate),
            baseline,
            versions,
            args.days,
            rows,
        )
    )


if __name__ == "__main__":
    main()
