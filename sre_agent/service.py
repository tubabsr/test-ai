"""Gathers inputs from Loki, Prometheus, and the Kubernetes API, then runs the pipeline."""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import RCAReport
from .pipeline import analyze
from .sources import (DEFAULT_QUERIES, LokiClient, PrometheusClient, check_label,
                      list_events, logql_for)


@dataclass(frozen=True)
class Settings:
    loki_url: str
    prometheus_url: str
    loki_token: Optional[str]
    anthropic_api_key: Optional[str]
    model: str
    baseline_minutes: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            loki_url=os.environ.get("LOKI_URL", "http://loki.monitoring.svc:3100"),
            prometheus_url=os.environ.get("PROMETHEUS_URL", "http://prometheus.monitoring.svc:9090"),
            loki_token=os.environ.get("LOKI_TOKEN") or None,
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
        )


def run_analysis(settings: Settings, *, namespace: str, workload: str, minutes: int = 30,
                 end: Optional[datetime] = None, selector: Optional[str] = None) -> RCAReport:
    check_label(namespace, "namespace")
    check_label(workload, "workload")
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    baseline_start = start - timedelta(minutes=settings.baseline_minutes)

    loki = LokiClient(settings.loki_url, token=settings.loki_token)
    prom = PrometheusClient(settings.prometheus_url)

    logs = loki.query_logs(logql_for(namespace, selector), start, end)
    metrics = prom.query_many(DEFAULT_QUERIES, namespace=namespace,
                              start=baseline_start, end=end)
    events = list_events(namespace, baseline_start, end)

    return analyze(
        namespace=namespace,
        workload=workload,
        window_start=start,
        window_end=end,
        logs=logs,
        events=events,
        metrics=metrics,
        api_key=settings.anthropic_api_key,
        model=settings.model,
    )
