"""Five Whys analysis.

Each step either cites evidence that exists in the book (verified) or says it is
not established. Steps without evidence are never filled in with plausible prose.
"""
from __future__ import annotations

from typing import Any, Optional

from .evidence import EvidenceBook
from .models import Hypothesis, WhyStep

UNVERIFIED = "Not established from the collected evidence."

# (question, answer if evidence found, evidence tags, text if not found)
CHAINS: dict[str, list[tuple[str, str, tuple[str, ...], str]]] = {
    "memory_limit": [
        ("Why did requests fail?",
         "Requests failed because pods were restarting after being killed.",
         ("crashloop", "signature:oom_killed"),
         "Error logs exist, but no restart or termination signal was captured."),
        ("Why were pods restarting?",
         "The kernel OOM killer terminated the containers.",
         ("oom",),
         "No OOMKilled event was found. Check node logs for kernel OOM messages."),
        ("Why did the OOM killer trigger?",
         "Working-set memory reached the container memory limit.",
         ("memory_shift",),
         "Usage was not compared with the limit. Check container_memory_working_set_bytes against the limit."),
        ("Why did memory usage rise, or the limit stay low?",
         "Usage rose above its pre-incident baseline. Either traffic increased or a change raised per-request memory.",
         ("memory_shift", "rollout"),
         "Traffic and release data are needed to tell load growth from a regression."),
        ("Why was this not caught before customers were affected?",
         UNVERIFIED,
         (),
         "Alert history was not queried. Check whether a memory-near-limit alert exists and when it fired."),
    ],
    "config_change": [
        ("Why did requests fail?",
         "Requests failed on a missing setting or a denied credential.",
         ("signature:config_missing", "signature:auth_denied"),
         "Error text did not name a configuration or credential problem."),
        ("Why was the setting or credential wrong?",
         "A rollout happened shortly before errors began.",
         ("rollout",),
         "No rollout was seen. Check Secret and ConfigMap edit history outside Kubernetes events."),
        ("What changed in the release?",
         UNVERIFIED,
         (),
         "Diff the current revision against the last known-good revision (rollout history or GitOps history)."),
        ("Why did the change pass review and deploy?",
         UNVERIFIED,
         (),
         "Requires a process review. This is not visible in telemetry."),
        ("Why was the defect not caught before production?",
         UNVERIFIED,
         (),
         "Requires staging and test history."),
    ],
    "dependency": [
        ("Why did requests fail?",
         "Calls to the dependency were refused, or they waited for a free connection.",
         ("signature:connection_refused", "signature:db_pool_exhausted"),
         "No dependency-side failure was captured in logs."),
        ("Why were calls waiting or refused?",
         "Dependency latency rose, so connections stayed busy until they timed out.",
         ("signature:timeout", "latency_shift"),
         "No latency evidence. A client-side connection leak also fits these errors."),
        ("Why did the dependency slow or refuse connections?",
         UNVERIFIED,
         (),
         "Dependency health metrics were out of scope. Query the dependency's own dashboards and logs."),
        ("Why did load or connection demand increase?",
         UNVERIFIED,
         (),
         "Client request rate and pool size metrics were not collected."),
        ("Why was there no backpressure or fallback?",
         UNVERIFIED,
         (),
         "Design question for the service owners."),
    ],
}

_GENERIC_QUESTIONS = [
    "Why did the service fail?",
    "Why did that condition occur?",
    "Why was it not detected earlier?",
    "Why did the system not recover on its own?",
    "Why does this failure mode exist?",
]


def _generic(hyp: Hypothesis) -> list[WhyStep]:
    steps = [WhyStep(1, _GENERIC_QUESTIONS[0], hyp.statement, list(hyp.evidence_ids), bool(hyp.evidence_ids))]
    for level in range(2, 6):
        steps.append(WhyStep(level, _GENERIC_QUESTIONS[level - 1],
                             "Requires investigation beyond the logs, events, and metrics in scope.",
                             [], False))
    return steps


def deterministic(hyp: Hypothesis, book: EvidenceBook) -> list[WhyStep]:
    chain = CHAINS.get(hyp.key)
    if chain is None:
        return _generic(hyp)
    steps: list[WhyStep] = []
    for level, (question, answer, tags, unverified) in enumerate(chain, start=1):
        ids = book.ids_tagged(*tags) if tags else []
        if ids:
            steps.append(WhyStep(level, question, answer, ids, True))
        else:
            steps.append(WhyStep(level, question, unverified, [], False))
    return steps


def validate_llm_steps(raw: Any, book: EvidenceBook) -> Optional[list[WhyStep]]:
    """Accept LLM output only if every citation resolves to real evidence.

    Any unknown evidence ID rejects the whole chain. Partial acceptance would let
    fabricated citations slip through next to real ones.
    """
    if not isinstance(raw, dict):
        return None
    steps = raw.get("five_whys")
    if not isinstance(steps, list) or not 3 <= len(steps) <= 5:
        return None

    validated: list[WhyStep] = []
    for i, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            return None
        question = str(step.get("question", "")).strip()
        answer = str(step.get("answer", "")).strip()
        cited = step.get("evidence_ids", [])
        if not question or not answer or not isinstance(cited, list):
            return None
        if not all(isinstance(x, str) and x in book for x in cited):
            return None
        validated.append(WhyStep(i, question, answer, list(cited), verified=bool(cited)))
    return validated
