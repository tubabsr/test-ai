"""Analysis pipeline. Pure: no network I/O. sources.py and service.py handle I/O."""
from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional, Sequence

from . import five_whys, llm, remediation, root_cause
from .detection import detect
from .evidence import collect_evidence
from .models import (SEVERITY_RANK, KubeEvent, LogLine, MetricSeries, RCAReport, Severity)
from .redaction import redact

log = logging.getLogger(__name__)

STANDING_QUESTIONS = [
    "Were any Secret, ConfigMap, RBAC, or dependency changes made in the window? "
    "Kubernetes events do not record them.",
    "What was the customer-facing impact? This analysis measures error signals, not user impact. "
    "Attach SLI data to confirm.",
]


def analyze(
    *,
    namespace: str,
    workload: str,
    window_start: datetime,
    window_end: datetime,
    logs: Sequence[LogLine],
    events: Sequence[KubeEvent],
    metrics: Sequence[MetricSeries],
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-5-5",
    now: Optional[datetime] = None,
) -> RCAReport:
    now = now or datetime.now(timezone.utc)

    # Redact before anything else touches the text, including the LLM.
    logs = [replace(line, message=redact(line.message)) for line in logs]

    findings = detect(logs)
    book = collect_evidence(findings, events, metrics, incident_start=window_start)

    hypotheses = root_cause.rank(book)
    root, contributing = hypotheses[0], hypotheses[1:]

    whys = five_whys.deterministic(root, book)
    mode = "deterministic"
    extra_questions: list[str] = []

    if api_key and root.evidence_ids:
        try:
            raw = llm.request_whys(llm.build_prompt(root, book), api_key=api_key, model=model)
            validated = five_whys.validate_llm_steps(raw, book)
            if validated is not None:
                whys, mode = validated, "llm-validated"
                extra_questions += [q for q in raw.get("open_questions", []) if isinstance(q, str)]
            else:
                extra_questions.append(
                    "LLM narrative rejected because it cited evidence not in this report. "
                    "The deterministic chain was used.")
        except Exception as exc:  # network, auth, or parse failure must not fail the RCA
            log.warning("LLM narration unavailable: %s", exc)
            extra_questions.append("LLM narration unavailable. The deterministic chain was used.")

    timeline = sorted(
        ((e.at, e.source, f"[{e.id}] {e.summary}") for e in book.items if e.at),
        key=lambda item: item[0],
    )

    error_lines = sum(f.count for f in findings if SEVERITY_RANK[f.severity] >= SEVERITY_RANK[Severity.ERROR])
    pods = {p for f in findings for p in f.pods}
    if findings:
        impact = (f"{error_lines} error-level log line(s) across {len(pods)} pod(s). "
                  "Customer impact was not measured in this analysis.")
        summary = (
            f"{len(findings)} distinct error pattern(s) appeared in `{namespace}` between "
            f"{window_start:%H:%M} and {window_end:%H:%M} UTC. "
            f"Leading hypothesis: {root.title} (confidence: {root.confidence.value}, "
            f"{len(root.evidence_ids)} supporting evidence item(s))."
        )
    else:
        impact = "No error patterns were detected in logs for this window."
        summary = (f"No error patterns were detected in `{namespace}` between "
                   f"{window_start:%H:%M} and {window_end:%H:%M} UTC. "
                   "Widen the window or check whether logs are being collected.")

    open_questions = list(dict.fromkeys(
        root.open_checks
        + [step.answer for step in whys if not step.verified]
        + extra_questions
        + STANDING_QUESTIONS
    ))

    remediations = remediation.guard(
        remediation.recommend(root, namespace=namespace, workload=workload),
        namespace=namespace,
    )

    return RCAReport(
        incident_id=f"INC-{window_start:%Y%m%d-%H%M}-{namespace}",
        namespace=namespace,
        workload=workload,
        window_start=window_start,
        window_end=window_end,
        generated_at=now,
        analysis_mode=mode,
        summary=summary,
        impact=impact,
        timeline=timeline,
        findings=findings,
        root_cause=root,
        contributing=contributing,
        five_whys=whys,
        remediations=remediations,
        evidence=book.items,
        open_questions=open_questions,
    )
