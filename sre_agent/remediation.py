"""Remediation recommendations.

This module never executes anything. Mutating commands are emitted as text for a
human to review, each with preconditions and a rollback. The guard removes
commands that are never acceptable in an automated recommendation.
"""
from __future__ import annotations

import re

from .models import Hypothesis, Remediation, Risk

PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
# Automated recommendations never delete, force, drain, or hit every object at once.
FORBIDDEN = re.compile(
    r"\bdelete\b|--force|--grace-period=0|\bdrain\b|--all(?![-\w])",
    re.IGNORECASE,
)


def _r(title: str, risk: Risk, rationale: str, commands: list[str],
       rollback: list[str], preconditions: list[str], evidence_ids: list[str]) -> Remediation:
    return Remediation(
        title=title, risk=risk, rationale=rationale, commands=commands, rollback=rollback,
        preconditions=preconditions, evidence_ids=list(evidence_ids),
        requires_approval=risk is not Risk.READ_ONLY,
    )


def recommend(hyp: Hypothesis, *, namespace: str, workload: str) -> list[Remediation]:
    ns, wl, ids = namespace, workload, hyp.evidence_ids

    if hyp.key == "memory_limit":
        return [
            _r("Confirm the configured limit against live usage", Risk.READ_ONLY,
               "Establishes the actual limit and peak usage before any change.",
               [f"kubectl -n {ns} get deploy {wl} -o jsonpath='{{.spec.template.spec.containers[*].resources}}'",
                f"kubectl -n {ns} top pod -l app={wl} --containers"],
               [], ["metrics-server is installed"], ids),
            _r("Raise the memory limit as a stopgap (up to 1.5x current)", Risk.REVERSIBLE,
               "Buys time while the root cause is investigated. Restores service but does not fix a leak.",
               [f"kubectl -n {ns} set resources deploy/{wl} --limits=memory=<new-limit>"],
               [f"kubectl -n {ns} set resources deploy/{wl} --limits=memory=<previous-limit>"],
               ["Record the current limit before the change",
                "Nodes have allocatable memory for the larger limit (kubectl describe node)",
                "PodDisruptionBudget allows a rolling restart (kubectl get pdb)",
                "No ResourceQuota blocks the increase (kubectl describe quota)"],
               ids),
            _r("Capture a memory profile from a high-usage pod", Risk.READ_ONLY,
               "Separates a leak (growth over time) from a legitimate working set that needs a larger limit.",
               [f"kubectl -n {ns} top pod -l app={wl} --containers"],
               [], ["Profiling endpoint or tooling exists for this runtime"], ids),
        ]

    if hyp.key == "config_change":
        return [
            _r("Review rollout history and recent events", Risk.READ_ONLY,
               "Identifies the last known-good revision and confirms timing against the error onset.",
               [f"kubectl -n {ns} rollout history deploy/{wl}",
                f"kubectl -n {ns} get events --sort-by=.lastTimestamp | tail -n 50"],
               [], [], ids),
            _r("Roll back to the last known-good revision", Risk.REVERSIBLE,
               "Reverts the most likely change. Fast and reversible, but only if the timing matches.",
               [f"kubectl -n {ns} rollout undo deploy/{wl} --to-revision=<last-known-good>"],
               [f"kubectl -n {ns} rollout undo deploy/{wl} --to-revision=<current-revision>"],
               ["Rollout timing matches error onset in the timeline",
                "Last-known-good revision is identified and was healthy",
                "Change owner is notified"],
               ids),
        ]

    if hyp.key == "certificate":
        return [
            _r("Check certificate expiry and subject", Risk.READ_ONLY,
               "Confirms whether the certificate is expired or mismatched.",
               [f"kubectl -n {ns} get secret <tls-secret> -o jsonpath='{{.data.tls\\.crt}}' | base64 -d | openssl x509 -noout -enddate -subject"],
               [], ["Name of the TLS secret is known"], ids),
            _r("Restart workload after certificate rotation", Risk.REVERSIBLE,
               "Only useful after a valid certificate is in place. Restart alone does not fix an expired certificate.",
               [f"kubectl -n {ns} rollout restart deploy/{wl}"],
               [f"kubectl -n {ns} rollout undo deploy/{wl}"],
               ["New certificate validated against the failing host", "Previous Secret value saved"],
               ids),
        ]

    if hyp.key == "dependency":
        return [
            _r("Check dependency endpoints and pool metrics", Risk.READ_ONLY,
               "Shows whether the dependency has ready backends.",
               [f"kubectl -n {ns} get endpoints <dependency-service>",
                f"kubectl -n {ns} logs deploy/{wl} --since=30m | grep -i -E 'pool|refused|timeout' | tail -n 100"],
               [], [], ids),
            _r("Lower client connection pool size to protect the dependency", Risk.REVERSIBLE,
               "Reduces pressure on the dependency during recovery. May reduce throughput.",
               [f"kubectl -n {ns} set env deploy/{wl} DB_POOL_MAX=<lower-value>"],
               [f"kubectl -n {ns} set env deploy/{wl} DB_POOL_MAX=<current-value>"],
               ["Service owner accepts the throughput impact", "Current pool size is recorded"],
               ids),
        ]

    if hyp.key == "dns":
        return [
            _r("Check CoreDNS health and recent errors", Risk.READ_ONLY,
               "Determines whether resolution is failing cluster-wide or only for one name.",
               ["kubectl -n kube-system get pods -l k8s-app=kube-dns",
                "kubectl -n kube-system logs -l k8s-app=kube-dns --since=30m --tail=200"],
               [], [], ids),
        ]

    if hyp.key == "application_panic":
        return [
            _r("Match the failing trace to the running image", Risk.READ_ONLY,
               "Determines whether the crash is tied to the current release.",
               [f"kubectl -n {ns} get deploy {wl} -o jsonpath='{{.spec.template.spec.containers[*].image}}'"],
               [], [], ids),
            _r("Roll back to the previous release", Risk.REVERSIBLE,
               "Restores the prior version if the crash is a regression.",
               [f"kubectl -n {ns} rollout undo deploy/{wl}"],
               [f"kubectl -n {ns} rollout undo deploy/{wl} --to-revision=<current-revision>"],
               ["Previous revision was healthy in staging or earlier production"],
               ids),
        ]

    if hyp.key == "latency":
        return [
            _r("Check CPU throttling and per-route latency", Risk.READ_ONLY,
               "Separates an application slowdown from resource starvation.",
               [f"kubectl -n {ns} top pod -l app={wl} --containers"],
               [], ["Tracing or per-route metrics are available"], ids),
        ]

    return [
        _r("Collect more data before acting", Risk.READ_ONLY,
           "No known pattern matched. Gather cluster-level context first.",
           [f"kubectl -n {ns} get events --sort-by=.lastTimestamp | tail -n 100",
            f"kubectl -n {ns} describe deploy {wl}"],
           [], [], ids),
    ]


def guard(items: list[Remediation], *, namespace: str) -> list[Remediation]:
    """Drop commands that are never acceptable; add change-management gates for protected namespaces."""
    safe: list[Remediation] = []
    for item in items:
        if any(FORBIDDEN.search(cmd) for cmd in item.commands + item.rollback):
            continue
        if namespace in PROTECTED_NAMESPACES and item.risk is not Risk.READ_ONLY:
            item.preconditions.append("Protected namespace: the change must go through change management")
        item.requires_approval = item.risk is not Risk.READ_ONLY
        safe.append(item)
    return safe
