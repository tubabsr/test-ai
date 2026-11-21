"""Error detection: classify log lines into signatures, then group repeats into findings.

Classification is first-match-wins, so specific signatures must precede generic ones.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .models import Finding, LogLine, Severity, SEVERITY_RANK


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    severity: Severity
    pattern: re.Pattern


def _sig(name: str, category: str, severity: Severity, regex: str) -> Signature:
    return Signature(name, category, severity, re.compile(regex, re.IGNORECASE))


SIGNATURES: tuple[Signature, ...] = (
    _sig("oom_killed", "resource", Severity.CRITICAL,
         r"OOMKilled|out of memory|OutOfMemoryError|MemoryError"),
    _sig("db_pool_exhausted", "dependency", Severity.ERROR,
         r"pool .{0,40}exhausted|too many connections|timeout acquiring connection"),
    _sig("connection_refused", "dependency", Severity.ERROR,
         r"connection refused|ECONNREFUSED"),
    _sig("dns_failure", "network", Severity.ERROR,
         r"no such host|NXDOMAIN|Name or service not known"),
    _sig("tls_failure", "security", Severity.ERROR,
         r"x509: certificate|certificate has expired|tls: handshake failure"),
    _sig("auth_denied", "security", Severity.ERROR,
         r"permission denied|forbidden|unauthorized|\b40[13]\b"),
    _sig("config_missing", "config", Severity.ERROR,
         r"environment variable .{0,40}(?:not set|missing)|missing required (?:config|setting)|no such file or directory"),
    _sig("timeout", "latency", Severity.WARNING,
         r"deadline exceeded|timed? ?out|context canceled"),
    _sig("panic", "application", Severity.CRITICAL,
         r"panic:|Traceback \(most recent call last\)|Exception in thread|NullPointerException"),
    _sig("http_5xx", "application", Severity.ERROR,
         r"\bstatus[=: ]5\d\d\b"),
    _sig("generic_error", "application", Severity.WARNING,
         r"\b(?:ERROR|FATAL|CRITICAL|SEVERE)\b"),
)

_NORMALIZERS = (
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<id>"),
    (re.compile(r"\d+(?:\.\d+)?"), "<n>"),
    (re.compile(r"\s+"), " "),
)


def template(message: str) -> str:
    """Collapse variable parts (IDs, IPs, numbers) so repeats group together."""
    text = message.strip()
    for pattern, replacement in _NORMALIZERS:
        text = pattern.sub(replacement, text)
    return text[:200]


def classify(message: str) -> Optional[Signature]:
    for sig in SIGNATURES:
        if sig.pattern.search(message):
            return sig
    return None


def detect(lines: Iterable[LogLine]) -> list[Finding]:
    groups: dict[tuple[str, str], dict] = {}
    for line in lines:
        sig = classify(line.message)
        if sig is None:
            continue
        key = (sig.name, template(line.message))
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "sig": sig, "count": 0, "pods": set(),
                "first": line.timestamp, "last": line.timestamp, "sample": line.message,
            }
        group["count"] += 1
        group["pods"].add(line.pod)
        group["first"] = min(group["first"], line.timestamp)
        group["last"] = max(group["last"], line.timestamp)

    findings = [
        Finding(
            signature=g["sig"].name,
            category=g["sig"].category,
            severity=g["sig"].severity,
            count=g["count"],
            pods=sorted(g["pods"]),
            first_seen=g["first"],
            last_seen=g["last"],
            sample=g["sample"][:500],
        )
        for g in groups.values()
    ]
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -f.count))
    return findings
