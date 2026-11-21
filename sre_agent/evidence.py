"""Turns raw signals into numbered, tagged evidence.

The reasoning layers only see this book. A claim that cannot be traced to an
evidence ID cannot appear in the report.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from statistics import median
from typing import Optional, Sequence

from .models import Evidence, Finding, KubeEvent, MetricSeries, Severity, SEVERITY_RANK

EVENT_TAGS: dict[str, list[str]] = {
    "OOMKilling": ["oom"],
    "BackOff": ["crashloop"],
    "Unhealthy": ["probe"],
    "Evicted": ["eviction"],
    "FailedScheduling": ["scheduling"],
    "FailedMount": ["mount"],
    "NodeNotReady": ["node"],
    "Killing": ["killing"],
    "ScalingReplicaSet": ["rollout"],
}

# A rollout only counts as a change candidate if it happened shortly before the incident.
CHANGE_LOOKBACK = timedelta(minutes=30)


class EvidenceBook:
    def __init__(self) -> None:
        self.items: list[Evidence] = []
        self._by_id: dict[str, Evidence] = {}

    def add(self, kind: str, summary: str, source: str,
            at: Optional[datetime], tags: Sequence[str] = ()) -> str:
        eid = f"E{len(self.items) + 1}"
        item = Evidence(id=eid, kind=kind, summary=summary, source=source, at=at, tags=list(tags))
        self.items.append(item)
        self._by_id[eid] = item
        return eid

    def __contains__(self, eid: str) -> bool:
        return eid in self._by_id

    def tagged(self, *tags: str) -> list[Evidence]:
        wanted = set(tags)
        return [e for e in self.items if wanted.intersection(e.tags)]

    def ids_tagged(self, *tags: str) -> list[str]:
        return [e.id for e in self.tagged(*tags)]


def _shift(series: MetricSeries, incident_start: datetime, threshold: float):
    """Compare incident-window peak against the pre-incident median baseline."""
    pre = [v for t, v in series.points if t < incident_start]
    during = [v for t, v in series.points if t >= incident_start]
    if len(pre) < 3 or not during:
        return None  # not enough baseline to judge; do not guess
    base, peak = median(pre), max(during)
    if base <= 0:
        return (0.0, peak, None) if peak > 0 else None
    ratio = peak / base
    return (base, peak, ratio) if ratio >= threshold else None


def _fmt(value: float) -> str:
    """Human-readable magnitude for evidence summaries (bytes, rates, seconds)."""
    if abs(value) >= 1e6:
        return f"{value / 1e6:.1f}M"
    if abs(value) >= 1:
        return f"{value:.2f}"
    return f"{value:.4f}"


def _metric_tag(name: str) -> str:
    for needle, tag in (("memory", "memory_shift"), ("latency", "latency_shift"),
                        ("restart", "restart_shift"), ("error", "error_rate_shift")):
        if needle in name:
            return tag
    return "metric_shift"


def collect_evidence(findings: list[Finding], events: Sequence[KubeEvent],
                     metrics: Sequence[MetricSeries], *, incident_start: datetime,
                     shift_threshold: float = 1.5) -> EvidenceBook:
    book = EvidenceBook()

    for f in findings:
        tags = [f"signature:{f.signature}", f"category:{f.category}"]
        if SEVERITY_RANK[f.severity] >= SEVERITY_RANK[Severity.ERROR]:
            tags.append("error")
        eid = book.add(
            "log",
            f"{f.count} occurrence(s) of {f.signature} across {len(f.pods)} pod(s). "
            f"Sample: {f.sample[:160]}",
            "loki", f.first_seen, tags,
        )
        f.evidence_ids.append(eid)

    for e in events:
        tags = EVENT_TAGS.get(e.reason)
        if not tags:
            continue
        if tags == ["rollout"] and e.timestamp < incident_start - CHANGE_LOOKBACK:
            continue
        book.add(
            "event",
            f"{e.reason} on {e.kind}/{e.name} at {e.timestamp:%H:%M:%S} UTC. {e.message[:160]}",
            "kubernetes-events", e.timestamp, tags,
        )

    for series in metrics:
        shift = _shift(series, incident_start, shift_threshold)
        if shift is None:
            continue
        base, peak, ratio = shift
        change = f"{ratio:.1f}x baseline" if ratio is not None else "up from zero"
        book.add(
            "metric",
            f"{series.name}: baseline {_fmt(base)}, incident peak {_fmt(peak)} ({change}).",
            "prometheus", incident_start, [_metric_tag(series.name)],
        )

    return book
