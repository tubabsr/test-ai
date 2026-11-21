"""Renders an RCAReport as a blameless Markdown document."""
from __future__ import annotations

from datetime import datetime

from .models import RCAReport


def _t(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _refs(ids: list[str]) -> str:
    return ", ".join(ids) if ids else "none"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(r: RCAReport) -> str:
    out: list[str] = []
    w = out.append

    w(f"# RCA: {r.incident_id}\n")
    w(f"- **Namespace / workload:** `{r.namespace}` / `{r.workload}`")
    w(f"- **Window:** {_t(r.window_start)} to {_t(r.window_end)}")
    w(f"- **Analysis mode:** {r.analysis_mode}")
    w(f"- **Generated:** {_t(r.generated_at)}\n")

    w("## Summary\n")
    w(r.summary + "\n")

    w("## Impact\n")
    w(r.impact + "\n")

    w("## Timeline\n")
    if r.timeline:
        w("| Time (UTC) | Source | Event |")
        w("|---|---|---|")
        for ts, source, text in r.timeline:
            w(f"| {ts:%H:%M:%S} | {source} | {_cell(text)} |")
    else:
        w("No timestamped evidence was collected.")
    w("")

    rc = r.root_cause
    w("## Root cause\n")
    w(f"**{rc.title}** (confidence: {rc.confidence.value}). {rc.statement}\n")
    w(f"Evidence: {_refs(rc.evidence_ids)}\n")
    if rc.open_checks:
        w("Open checks:\n")
        for check in rc.open_checks:
            w(f"- {check}")
        w("")

    if r.contributing:
        w("## Other hypotheses considered\n")
        for h in r.contributing:
            w(f"**{h.title}** (confidence: {h.confidence.value}). Evidence: {_refs(h.evidence_ids)}\n")

    w("## Five whys\n")
    w("| # | Question | Answer | Evidence | Verified |")
    w("|---|---|---|---|---|")
    for step in r.five_whys:
        w(f"| {step.level} | {_cell(step.question)} | {_cell(step.answer)} "
          f"| {_refs(step.evidence_ids)} | {'yes' if step.verified else 'no'} |")
    w("")

    w("## Remediation\n")
    w("Nothing below was executed. Each change needs a named approver and a tested rollback.\n")
    for i, rem in enumerate(r.remediations, start=1):
        approval = "approval required" if rem.requires_approval else "no approval needed"
        w(f"### {i}. {rem.title}\n")
        w(f"Risk: `{rem.risk.value}` ({approval}). Evidence: {_refs(rem.evidence_ids)}\n")
        w(rem.rationale + "\n")
        if rem.preconditions:
            w("Preconditions:\n")
            for p in rem.preconditions:
                w(f"- {p}")
            w("")
        if rem.commands:
            w("```bash")
            w("\n".join(rem.commands))
            w("```\n")
        if rem.rollback:
            w("Rollback:\n")
            w("```bash")
            w("\n".join(rem.rollback))
            w("```\n")

    w("## Open questions\n")
    for q in r.open_questions:
        w(f"- {q}")
    w("")

    w("## Findings\n")
    if r.findings:
        w("| Signature | Category | Severity | Count | Pods | Evidence |")
        w("|---|---|---|---|---|---|")
        for f in r.findings:
            w(f"| {f.signature} | {f.category} | {f.severity.value} | {f.count} | "
              f"{len(f.pods)} | {_refs(f.evidence_ids)} |")
    else:
        w("No error signatures matched.")
    w("")

    w("## Evidence index\n")
    w("| ID | Kind | Source | Summary |")
    w("|---|---|---|---|")
    for e in r.evidence:
        w(f"| {e.id} | {e.kind} | {e.source} | {_cell(e.summary)} |")
    w("")

    w("## Method and limits\n")
    w("- Log text was redacted for credentials and personal data before analysis.")
    w("- Confidence rises only when an independent signal corroborates the error, such as a metric shift "
      "or a rollout. Certificate failures are the exception, because their error text is specific.")
    w("- Language model output, when used, was accepted only if every citation matched an ID in the evidence index. "
      "Otherwise the deterministic chain was used.")
    w("- Kubernetes events expire after about an hour by default. Older incidents need an external event store.")
    w("- This tool executes no commands and makes no changes to the cluster.")

    return "\n".join(out) + "\n"
