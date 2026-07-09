# =====================================================================
# Advanced Honeypot Suite — Dockerfile
# Multi-stage build: lean production image (~320MB)
# =====================================================================
FROM python:3.11-slim AS base

LABEL maintainer="HoneypotSuite"
LABEL description="Advanced Honeypot Threat Intelligence Platform"
LABEL version="2.0.0"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev gcc curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ───────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ──────────────────────────────────────────
COPY . .

# Create runtime directories
RUN mkdir -p logs alerts cache exports malware/samples malware/metadata \
             sessions yara_rules attacks sandbox /data

# ── Non-root user ─────────────────────────────────────────────
RUN groupadd -r honeypot && useradd -r -g honeypot honeypot
RUN chown -R honeypot:honeypot /app /data
USER honeypot

# ── Entrypoint ────────────────────────────────────────────────
EXPOSE 2222 8080 2121 3306 6379 9200 2525 8081 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["python", "run.py"]
