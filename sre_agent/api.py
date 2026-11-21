"""HTTP API and dashboard host.

Deploy behind an authenticating proxy (for example OAuth2 Proxy). This service does
not implement user authentication itself.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .models import RCAReport
from .rca import render_markdown
from .service import Settings, run_analysis
from .sources import DEFAULT_QUERIES, PrometheusClient

NAME = r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"
DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"

app = FastAPI(title="Kubernetes SRE Agent", version="0.1.0")
settings = Settings.from_env()
_incidents: dict[str, RCAReport] = {}  # in-memory; replace with a database for production


class AnalyzeRequest(BaseModel):
    namespace: str = Field(pattern=NAME)
    workload: str = Field(pattern=NAME)
    minutes: int = Field(default=30, ge=5, le=360)
    selector: Optional[str] = Field(default=None, max_length=200)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD)


@app.post("/api/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    try:
        report = run_analysis(settings, namespace=req.namespace, workload=req.workload,
                              minutes=req.minutes, selector=req.selector)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"analysis failed: {exc}")
    _incidents[report.incident_id] = report
    return asdict(report)


@app.get("/api/incidents")
def list_incidents() -> list[dict]:
    return [{"incident_id": r.incident_id, "namespace": r.namespace, "workload": r.workload,
             "generated_at": r.generated_at, "root_cause": r.root_cause.title,
             "confidence": r.root_cause.confidence.value}
            for r in sorted(_incidents.values(), key=lambda r: r.generated_at, reverse=True)]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict:
    report = _incidents.get(incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return asdict(report)


@app.get("/api/incidents/{incident_id}/markdown", response_class=PlainTextResponse)
def get_incident_markdown(incident_id: str) -> str:
    report = _incidents.get(incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return render_markdown(report)


@app.get("/api/metrics/overview")
def metrics_overview(
    namespace: str = Query(pattern=NAME),
    minutes: int = Query(default=60, ge=5, le=1440),
    step: str = Query(default="60s", pattern=r"^\d+s$"),
) -> dict:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    prom = PrometheusClient(settings.prometheus_url)
    try:
        series = prom.query_many(DEFAULT_QUERIES, namespace=namespace, start=start, end=end, step=step)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"prometheus unavailable: {exc}")
    return {"namespace": namespace, "series": [asdict(s) for s in series]}
