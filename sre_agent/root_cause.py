"""Ranks root-cause hypotheses.

A hypothesis is emitted only when specific evidence supports it. Confidence is
earned by corroboration: a direct error plus an independent signal (metric shift,
rollout) raises it. Anything not yet checked is listed as an open check, not
silently assumed away.
"""
from __future__ import annotations

from .evidence import EvidenceBook
from .models import CONFIDENCE_RANK, Confidence, Hypothesis


def rank(book: EvidenceBook) -> list[Hypothesis]:
    ids = book.ids_tagged
    hyps: list[Hypothesis] = []

    oom = ids("signature:oom_killed", "oom")
    if oom:
        mem = ids("memory_shift")
        hyps.append(Hypothesis(
            key="memory_limit",
            title="Memory limit exceeded (OOMKilled)",
            category="resource",
            statement="Containers were killed by the OOM killer after memory usage reached the container limit.",
            confidence=Confidence.HIGH if mem else Confidence.MEDIUM,
            evidence_ids=oom + mem,
            open_checks=[] if mem else [
                "No memory shift was found in the window, so usage growth is unconfirmed as the trigger. "
                "Compare working-set memory with the configured limit."
            ],
        ))

    tls = ids("signature:tls_failure")
    if tls:
        hyps.append(Hypothesis(
            key="certificate",
            title="Certificate validation failure",
            category="security",
            statement="TLS handshakes fail on certificate validation. The certificate is expired, "
                      "mismatched, or issued by an untrusted authority.",
            confidence=Confidence.HIGH,
            evidence_ids=tls,
            open_checks=["Check expiry and SANs for the failing host, and whether a rotation happened in the window."],
        ))

    cfg = ids("signature:config_missing", "signature:auth_denied")
    rollout = ids("rollout")
    if cfg:
        hyps.append(Hypothesis(
            key="config_change",
            title="Configuration or credential defect",
            category="config",
            statement="Errors name a missing setting or a denied credential. These usually follow a "
                      "change to config, secrets, or RBAC.",
            confidence=Confidence.HIGH if rollout else Confidence.MEDIUM,
            evidence_ids=cfg + rollout,
            open_checks=[] if rollout else [
                "No rollout in the lookback window. Secret, ConfigMap, and RBAC edits are not recorded "
                "in Kubernetes events; check audit logs or GitOps history."
            ],
        ))

    dep = ids("signature:db_pool_exhausted", "signature:connection_refused")
    if dep:
        slow = ids("latency_shift", "signature:timeout")
        hyps.append(Hypothesis(
            key="dependency",
            title="Downstream dependency unavailable or saturated",
            category="dependency",
            statement="Calls to a downstream dependency were refused, or they queued for connections "
                      "until they timed out.",
            confidence=Confidence.HIGH if slow else Confidence.MEDIUM,
            evidence_ids=dep + slow,
            open_checks=[] if slow else [
                "No latency or timeout evidence. A client-side connection leak also fits these errors."
            ],
        ))

    dns = ids("signature:dns_failure")
    if dns:
        hyps.append(Hypothesis(
            key="dns",
            title="DNS resolution failure",
            category="network",
            statement="Hostnames failed to resolve inside the cluster.",
            confidence=Confidence.MEDIUM,
            evidence_ids=dns,
            open_checks=["Check CoreDNS pod health and logs, and whether the hostname changed in the window."],
        ))

    panic = ids("signature:panic")
    if panic:
        hyps.append(Hypothesis(
            key="application_panic",
            title="Unhandled exception in application code",
            category="application",
            statement="The application raised an unhandled panic or exception. The trace points at code "
                      "rather than infrastructure.",
            confidence=Confidence.MEDIUM,
            evidence_ids=panic + ids("crashloop"),
            open_checks=["Match the trace to the running release. A rollback or canary would confirm a regression."],
        ))

    lat = ids("latency_shift")
    if lat and not dep:
        hyps.append(Hypothesis(
            key="latency",
            title="Latency regression without a clear error signature",
            category="latency",
            statement="Latency rose sharply, but no specific failure pattern matched. Request traces "
                      "are needed to locate the slow hop.",
            confidence=Confidence.LOW,
            evidence_ids=lat,
            open_checks=["Compare p99 by route and by upstream. Check CPU throttling and recent rollouts."],
        ))

    if not hyps:
        return [Hypothesis(
            key="insufficient_evidence",
            title="Insufficient evidence",
            category="unknown",
            statement="No known failure pattern matched the logs and events in the window. "
                      "Manual investigation is required.",
            confidence=Confidence.LOW,
            evidence_ids=[],
            open_checks=["Widen the time window.", "Check node and cluster-level events.", "Review deploy history."],
        )]

    hyps.sort(key=lambda h: (CONFIDENCE_RANK[h.confidence], len(h.evidence_ids)), reverse=True)
    return hyps
