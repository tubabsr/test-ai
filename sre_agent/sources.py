"""Read-only clients for Loki, Prometheus, and the Kubernetes API.

Nothing here writes to a cluster. User-supplied values are validated before they
are placed into LogQL or PromQL, so a bad selector cannot change the query.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Optional

from .models import KubeEvent, LogLine, MetricSeries

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_SELECTOR = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.]*="[A-Za-z0-9_.\-]*"$')
ERROR_FILTER = "(?i)error|fatal|panic|exception|oom|refused|timeout|x509|no such host|exhausted|forbidden"

# {ns} is replaced literally, not with str.format, because PromQL uses braces.
DEFAULT_QUERIES: dict[str, str] = {
    "memory_working_set": 'sum by (pod) (container_memory_working_set_bytes{namespace="{ns}",container!=""})',
    "restarts": 'sum by (pod) (increase(kube_pod_container_status_restarts_total{namespace="{ns}"}[5m]))',
    "p99_latency_seconds": 'histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{namespace="{ns}"}[5m])))',
    "error_rate": 'sum(rate(http_requests_total{namespace="{ns}",code=~"5.."}[5m])) / sum(rate(http_requests_total{namespace="{ns}"}[5m]))',
}


def check_label(value: str, what: str) -> str:
    if not _DNS_LABEL.match(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def logql_for(namespace: str, selector: Optional[str] = None) -> str:
    check_label(namespace, "namespace")
    matchers = f'namespace="{namespace}"'
    if selector:
        if not _SELECTOR.match(selector):
            raise ValueError('selector must look like key="value"')
        matchers += "," + selector
    return f'{{{matchers}}} |~ "{ERROR_FILTER}"'


def _ns(ts: datetime) -> str:
    return str(int(ts.timestamp() * 1e9))


class LokiClient:
    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 20.0) -> None:
        import httpx

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout)

    def query_logs(self, logql: str, start: datetime, end: datetime, limit: int = 5000) -> list[LogLine]:
        resp = self._client.get("/loki/api/v1/query_range", params={
            "query": logql, "start": _ns(start), "end": _ns(end),
            "limit": limit, "direction": "forward",
        })
        resp.raise_for_status()
        out: list[LogLine] = []
        for stream in resp.json()["data"]["result"]:
            labels = stream.get("stream", {})
            for ts_ns, line in stream.get("values", []):
                out.append(LogLine(
                    timestamp=datetime.fromtimestamp(int(ts_ns) / 1e9, tz=timezone.utc),
                    namespace=labels.get("namespace", ""),
                    pod=labels.get("pod", ""),
                    container=labels.get("container", ""),
                    message=line,
                ))
        out.sort(key=lambda line: line.timestamp)
        return out


class PrometheusClient:
    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
        import httpx

        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def query_range(self, promql: str, start: datetime, end: datetime,
                    step: str, name: str) -> list[MetricSeries]:
        resp = self._client.get("/api/v1/query_range", params={
            "query": promql, "start": start.timestamp(), "end": end.timestamp(), "step": step,
        })
        resp.raise_for_status()
        body = resp.json()
        if body.get("status") != "success":
            raise RuntimeError(body.get("error", "prometheus query failed"))

        series: list[MetricSeries] = []
        for item in body["data"]["result"]:
            points = []
            for ts, val in item.get("values", []):
                value = float(val)
                if not math.isnan(value):
                    points.append((datetime.fromtimestamp(float(ts), tz=timezone.utc), value))
            labels = ",".join(f"{k}={v}" for k, v in sorted(item.get("metric", {}).items()) if k != "__name__")
            full_name = f"{name}{{{labels}}}" if labels else name
            series.append(MetricSeries(name=full_name, points=points))
        return series

    def query_many(self, queries: dict[str, str], *, namespace: str,
                   start: datetime, end: datetime, step: str = "60s") -> list[MetricSeries]:
        check_label(namespace, "namespace")
        out: list[MetricSeries] = []
        for name, template in queries.items():
            out += self.query_range(template.replace("{ns}", namespace), start, end, step, name)
        return out


def _kube_api():
    from kubernetes import client, config  # lazy: only needed when the cluster is queried

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def list_events(namespace: str, start: datetime, end: datetime) -> list[KubeEvent]:
    check_label(namespace, "namespace")
    api = _kube_api()
    out: list[KubeEvent] = []
    for e in api.list_namespaced_event(namespace).items:
        ts = e.last_timestamp or e.event_time or (e.metadata.creation_timestamp if e.metadata else None)
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if not start <= ts <= end:
            continue
        obj = e.involved_object
        out.append(KubeEvent(
            timestamp=ts, namespace=namespace, kind=obj.kind or "", name=obj.name or "",
            reason=e.reason or "", message=e.message or "", event_type=e.type or "Normal",
        ))
    return out


def pod_logs_from_api(namespace: str, label_selector: str, since_seconds: int = 1800,
                      tail: int = 2000) -> list[LogLine]:
    """Fallback when Loki is unavailable. Reads logs directly from the kubelet via the API."""
    check_label(namespace, "namespace")
    api = _kube_api()
    out: list[LogLine] = []
    for pod in api.list_namespaced_pod(namespace, label_selector=label_selector).items:
        for container in pod.spec.containers:
            text = api.read_namespaced_pod_log(
                pod.metadata.name, namespace, container=container.name,
                since_seconds=since_seconds, tail_lines=tail, timestamps=True,
            )
            for raw in text.splitlines():
                ts_str, _, message = raw.partition(" ")
                ts_str = re.sub(r"(\.\d{6})\d+", r"\1", ts_str)  # Python fromisoformat takes microseconds
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                out.append(LogLine(ts, namespace, pod.metadata.name, container.name, message))
    return out
