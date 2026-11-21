# syntax=docker/dockerfile:1
# For reproducible builds, pin the base image by digest once you choose a version:
#   FROM python:3.12-slim@sha256:<digest>
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only what the service needs. Tests, manifests, and CI config stay out of the image.
COPY sre_agent ./sre_agent
COPY dashboard ./dashboard

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "sre_agent.api:app", "--host", "0.0.0.0", "--port", "8080"]
