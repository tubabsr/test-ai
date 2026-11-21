"""Optional narration layer.

The model receives numbered, already-redacted evidence and must cite IDs from it.
It has no tools and no cluster access. Its output is validated in five_whys.py
before it is used, and the pipeline falls back to the deterministic chain on failure.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .evidence import EvidenceBook
from .models import Hypothesis

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = (
    "You are a principal SRE writing a blameless root-cause analysis. "
    "Use ONLY the evidence IDs provided. Never invent metrics, counts, versions, or causes. "
    "If the evidence does not support a step, set evidence_ids to [] and say the step is not established. "
    "Respond with JSON only, no prose and no code fences, using this shape: "
    '{"five_whys": [{"level": 1, "question": "...", "answer": "...", "evidence_ids": ["E1"]}], '
    '"open_questions": ["..."]}. Use 3 to 5 steps.'
)


def build_prompt(hyp: Hypothesis, book: EvidenceBook) -> str:
    lines = [
        f"Root-cause hypothesis: {hyp.title}. {hyp.statement}",
        "",
        "Evidence (cite only these IDs):",
    ]
    lines += [f"{e.id} [{e.kind}] {e.summary}" for e in book.items]
    lines += ["", "Open checks: " + ("; ".join(hyp.open_checks) or "none")]
    return "\n".join(lines)


def parse_json(text: str) -> Any:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    return json.loads(cleaned)


def request_whys(prompt: str, *, api_key: str, model: str, timeout: float = 60.0) -> Any:
    import httpx  # imported lazily so the analysis core has no hard network dependency

    response = httpx.post(
        ANTHROPIC_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1200,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=timeout,
    )
    response.raise_for_status()
    text = "".join(
        block.get("text", "")
        for block in response.json().get("content", [])
        if block.get("type") == "text"
    )
    return parse_json(text)
