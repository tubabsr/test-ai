"""Core data model. Every conclusion must trace back to evidence IDs (E1, E2, ...)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


SEVERITY_RANK = {Severity.WARNING: 1, Severity.ERROR: 2, Severity.CRITICAL: 3}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


CONFIDENCE_RANK = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}


class Risk(str, Enum):
    READ_ONLY = "read_only"    # observes state only; safe to run
    REVERSIBLE = "reversible"  # changes state; has a tested rollback; needs approval
    DISRUPTIVE = "disruptive"  # may cause downtime or data loss; needs change review


@dataclass(frozen=True)
class LogLine:
    timestamp: datetime
    namespace: str
    pod: str
    container: str
    message: str


@dataclass(frozen=True)
class KubeEvent:
    timestamp: datetime
    namespace: str
    kind: str
    name: str
    reason: str
    message: str
    event_type: str


@dataclass(frozen=True)
class MetricSeries:
    name: str
    points: list[tuple[datetime, float]]  # ordered by time


@dataclass
class Evidence:
    id: str
    kind: str          # log | event | metric
    summary: str
    source: str        # loki | kubernetes-events | prometheus
    at: Optional[datetime]
    tags: list[str] = field(default_factory=list)


@dataclass
class Finding:
    signature: str
    category: str
    severity: Severity
    count: int
    pods: list[str]
    first_seen: datetime
    last_seen: datetime
    sample: str
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    key: str
    title: str
    category: str
    statement: str
    confidence: Confidence
    evidence_ids: list[str]
    open_checks: list[str] = field(default_factory=list)


@dataclass
class WhyStep:
    level: int
    question: str
    answer: str
    evidence_ids: list[str]
    verified: bool


@dataclass
class Remediation:
    title: str
    risk: Risk
    rationale: str
    commands: list[str]
    rollback: list[str]
    preconditions: list[str]
    evidence_ids: list[str]
    requires_approval: bool


@dataclass
class RCAReport:
    incident_id: str
    namespace: str
    workload: str
    window_start: datetime
    window_end: datetime
    generated_at: datetime
    analysis_mode: str
    summary: str
    impact: str
    timeline: list[tuple[datetime, str, str]]
    findings: list[Finding]
    root_cause: Hypothesis
    contributing: list[Hypothesis]
    five_whys: list[WhyStep]
    remediations: list[Remediation]
    evidence: list[Evidence]
    open_questions: list[str]
