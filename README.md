# Kubernetes SRE Agent

An evidence-first incident analysis tool for Kubernetes. It reads logs, events, and metrics for a workload over a time window, detects error patterns, ranks root-cause hypotheses, produces a Five Whys chain and a blameless RCA report, and recommends remediations. It does not change the cluster.

## Principles

1. **Every claim cites evidence.** Each finding, hypothesis, and why-step references numbered evidence items (E1, E2, ...). A step with no evidence is marked "not established" rather than filled with plausible prose.
2. **Confidence is earned.** A direct error alone gives medium confidence for most patterns. Adding an independent signal, such as a metric shift or a rollout that precedes the error, raises it to high. Each hypothesis lists the checks still open.
3. **Read-only by default.** The service account has only get, list, and watch permissions. Recommended changes are printed as text with preconditions and a rollback. Nothing executes.
4. **Guardrails on recommendations.** Automated recommendations never contain `delete`, `--force`, `drain`, `--grace-period=0`, or `--all`. Changes in `kube-system` and similar namespaces are marked as needing change management.
5. **Redact before analysis.** Credentials, tokens, JWTs, AWS keys, database passwords, and email addresses are removed from log text before detection and before any LLM call.
6. **The LLM narrates; it does not decide.** When `ANTHROPIC_API_KEY` is set, the model writes the Five Whys over numbered evidence. Its output is accepted only if every citation resolves to a real evidence ID. Otherwise the deterministic chain is used. The model has no tools and no cluster access.

## Architecture

```
Loki (logs) ─┐
Prometheus ──┼─► sources.py ─► redaction ─► detection ─► evidence book ─► root_cause ─► five_whys ─┐
K8s events ──┘                                                 ▲                                  ├─► rca.py (Markdown)
                                                               │                                  └─► remediation.py (guarded)
                                              optional LLM narration (validated) ──────────────────┘
                                                               │
                              api.py (FastAPI) ◄── dashboard/index.html (live charts, RCA panel)
                              cli.py           ◄── terminal use
```

| Module | Responsibility |
|---|---|
| `models.py` | Shared data types |
| `redaction.py` | Secret and PII removal |
| `detection.py` | Error signatures (first match wins), normalization, grouping |
| `evidence.py` | Numbered, tagged evidence; metric shift detection against a pre-incident baseline |
| `root_cause.py` | Hypothesis ranking with corroboration rules and open checks |
| `five_whys.py` | Deterministic evidence-linked chains; strict validation of LLM output |
| `llm.py` | Optional narration client (lazy `httpx` import) |
| `remediation.py` | Risk-tiered recommendations and the command guard |
| `pipeline.py` | Pure orchestration, no I/O |
| `rca.py` | Blameless Markdown report |
| `sources.py` | Loki, Prometheus, and Kubernetes readers with input validation |
| `service.py` | Settings and I/O orchestration |
| `api.py`, `cli.py` | HTTP and command-line entry points |

## Running locally

Analysis core and tests (standard library only):

```bash
python3 -m unittest discover -s tests -t . -v
```

Full service:

```bash
pip install -r requirements.txt
export LOKI_URL=http://localhost:3100
export PROMETHEUS_URL=http://localhost:9090
export ANTHROPIC_API_KEY=...          # optional; without it the analysis is fully deterministic
uvicorn sre_agent.api:app --port 8080 # dashboard at http://localhost:8080/
```

CLI:

```bash
python -m sre_agent.cli analyze --namespace shop --workload checkout --minutes 30 --out rca.md
```

## API

| Method and path | Purpose |
|---|---|
| `POST /api/analyze` | Body: `{namespace, workload, minutes, selector?}`. Returns the full report as JSON. |
| `GET /api/incidents` | Recent analyses (in memory) |
| `GET /api/incidents/{id}` | One report as JSON |
| `GET /api/incidents/{id}/markdown` | One report as Markdown |
| `GET /api/metrics/overview` | Error rate, p99, restarts, and memory series for the dashboard |
| `GET /healthz` | Liveness and readiness |

## Deploying

1. Build and push the image. The Dockerfile is not included; the command is `uvicorn sre_agent.api:app --host 0.0.0.0 --port 8080`.
2. Create the Anthropic key secret, if used: `kubectl -n sre-agent create secret generic sre-agent-secrets --from-literal=anthropic-api-key=...`
3. Apply `deploy/k8s.yaml`, then `deploy/prometheus-rules.yaml`. Import `deploy/grafana-dashboard.json` into Grafana and set the datasource variables.
4. Put the service behind an authenticating proxy such as OAuth2 Proxy. The app has no user authentication of its own.

## Limits and known gaps

- **Not tested against a live cluster.** The analysis core has unit tests, and they pass. The Loki, Prometheus, and Kubernetes clients, the API, and the dashboard have not been run against real systems. Treat the first run as a validation step.
- **Kubernetes events expire.** They are kept for about an hour by default. Longer lookbacks need an event exporter such as `kubernetes-event-exporter` feeding Loki.
- **Configuration changes are invisible to events.** Secret, ConfigMap, and RBAC edits do not generate events. The report says so and lists them as an open question. Audit logs or GitOps history are the real source.
- **Customer impact is not measured.** Error counts are signals, not impact. Attach SLI data before stating impact.
- **Single-instance state.** Incidents are held in memory. Use a database for history and for multi-replica deployments.
- **Log sampling.** Loki returns up to 5,000 lines per query. Very noisy workloads should use a narrower window or a selector.
- **Signature coverage is finite.** Unknown failure modes produce "insufficient evidence", which is intentional. Add signatures and hypotheses as incidents teach you new patterns.

## Extending

- Add a signature: a regex in `detection.SIGNATURES`, plus a rule in `root_cause.rank`, plus a chain in `five_whys.CHAINS` and a recommendation branch in `remediation.recommend`.
- Each new hypothesis should state its open checks. An honest "not checked yet" is more useful during an incident than a confident guess.
