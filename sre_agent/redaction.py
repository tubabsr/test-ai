"""Redacts credentials and personal data from log text.

Runs before detection and before any model call, so secrets never reach an LLM
or the generated report.
"""
from __future__ import annotations

import re

_RULES = (
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-~+/]+=*"), r"\1[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "[REDACTED_JWT]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(postgres(?:ql)?://[^:\s]+:)[^@\s]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\",;&]+"),
     r"\1\2[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
)


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
