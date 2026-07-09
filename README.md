# Honeypot Suite
<p align="center">
  <img src="assets/banner.png" alt="Honeypot Suite Banner" width="100%">
</p>

<h1 align="center">Honeypot Suite</h1>

<p align="center">
Advanced Multi-Service Cybersecurity Honeypot with Real-Time Attack Monitoring
</p>

<p align="center">

<img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Flask-Web_Framework-000000?logo=flask">
<img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white">
<img src="https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite">
<img src="https://img.shields.io/badge/MITRE-ATT%26CK-red">
<img src="https://img.shields.io/badge/YARA-Malware-orange">
<img src="https://img.shields.io/badge/STIX-2.1-success">
<img src="https://img.shields.io/badge/License-MIT-green">

</p>
A multi-protocol honeypot platform that captures, classifies, and exports
attacker behavior for threat-intelligence consumption — by a SOC team, a
CERT, or an automated detection pipeline.

It emulates SSH, HTTP, FTP, MySQL, Redis, SMTP, DNS, HTTPS, Elasticsearch,
and an admin-panel decoy, then enriches every connection with GeoIP/ASN
data, maps observed behavior to MITRE ATT&CK techniques, scans uploaded
files with YARA, and exposes everything through a live web dashboard and
a REST API. Findings can be exported as STIX 2.1 bundles for sharing with
CERTs, ISACs, or any TAXII-compatible platform.
A multi-protocol honeypot platform that captures, classifies, and exports
attacker behavior...

## ✨ Features

- Multi-Service Honeypot (SSH, HTTP, FTP)
- Interactive Decoy Services
- Real-Time SOC Dashboard
- Live Attack Map
- GeoIP & ASN Mapping
- MITRE ATT&CK Mapping
- YARA Malware Scanning
- Evidence Hashing (SHA-256)
- Chain of Custody Tracking
- STIX 2.1 Export
- REST API
- Docker Deployment
- SQLite Database
- Threat Intelligence Pipeline

## Why this exists

Most student/hobby honeypot projects...
## Why this exists

Most student/hobby honeypot projects stop at "log attacker IPs to a text
file." This one is built to the bar of an actual SOC tool: a real
database instead of grep-able logs, a browser dashboard instead of a
desktop GUI tied to one machine, industry-standard detection (YARA,
MITRE ATT&CK) instead of ad-hoc string matching, and a threat-intel
export format (STIX 2.1) that downstream platforms can actually ingest.

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐
│ SSH Honeypot│  │HTTP Honeypot│  │ FTP Honeypot│  │ Decoy Services   │
│ (paramiko)  │  │ (fake portal)│ │ (fake FS)   │  │ MySQL/Redis/SMTP │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘
       │                │                │                  │
       └────────────────┴────────────────┴──────────────────┘
                              │
                    logger.log() / alert_system.trigger()
                    mitre_attack.map_and_log()
                              │
                  ┌───────────┴────────────┐
                  │   SQLAlchemy / SQLite   │   ← database.py
                  │  (events, alerts, IPs,  │
                  │ sessions, MITRE, malware)│
                  └───────────┬────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                      │
┌───────┴────────┐  ┌─────────┴─────────┐  ┌─────────┴─────────┐
│  Web Dashboard  │  │   YARA Scanner    │  │   STIX Exporter    │
│ Flask+SocketIO  │  │ (malware/payload  │  │ (2.1 bundles for   │
│  REST + live feed│ │   detection)      │  │  CERT/SIEM sharing)│
└─────────────────┘  └───────────────────┘  └─────────────────────┘
```

The original service files (`ssh_honeypot.py`, `http_honeypot.py`,
`ftp_honeypot.py`, `decoy_services.py`, `mitre_attack.py`,
`alert_system.py`) are untouched in their core logic. `run.py` patches
three integration points at startup — `logger.log()`,
`alert_system.trigger()`, `mitre_attack.map_and_log()` — to additionally
write into the database and push to the live dashboard, without
requiring changes to every call site across the codebase.

## What's new in v1.0.0

| Area | v1.0 (original) | v1.0.0 (this upgrade) |
|---|---|---|
| UI | Tkinter desktop GUI, one machine only | Browser-based dashboard, any device on the network |
| Storage | Per-service JSON line logs | SQLite (swappable to Postgres) via SQLAlchemy, with indexed queries |
| Malware detection | Magic bytes + 16 base64-obscured regex patterns | YARA rule engine — 18 industry-standard rules across webshells, reverse shells, exploits (Log4Shell, ShellShock), cryptominers, persistence |
| MITRE ATT&CK | 5 of 26 known scanner tools mapped to T1595 (audited gap, fixed) | All 26 scanner signatures mapped; coverage gap fixed in `mitre_attack.py` |
| Threat sharing | None | STIX 2.1 bundle export (TLP-marked, TAXII-compatible) |
| Deployment | `python main.py` on a desktop with a display | `docker-compose up -d`, headless, health-checked, non-root container |
| Configuration | Hardcoded ports/values across files | Single `config.yaml` + environment variable overrides for Docker/CI |
| Testing | None | 29 pytest tests covering DB, YARA, STIX, config layers |
| CI/CD | None | GitHub Actions: multi-version test matrix, Docker build smoke test, dependency CVE scan |

## Quick start

### Docker (recommended)

```bash
cp .env.example .env        # fill in secrets/API keys (all optional except dashboard secret)
docker-compose up -d
docker-compose logs -f honeypot
```

Dashboard: `http://localhost:5000` (default login `admin` / `admin` —
**change this**, see Security below).

### Local Python

```bash
pip install -r requirements.txt
# yara-python needs libyara; on Ubuntu/Debian:
#   sudo apt install libssl-dev && pip install yara-python
python run.py --init-db      # create the database
python run.py                # start everything
```

Flags:
- `--no-dashboard` — headless mode, services only (no web UI)
- `--dashboard-only` — web UI only, don't bind honeypot listener ports
- `--export-stix` — generate a STIX bundle from current DB contents and exit
- `--debug` — verbose Flask debug mode

## Configuration

Everything lives in `config.yaml` — ports, dashboard credentials, threat
intel API keys, alerting channels, YARA toggle, STIX TLP level. Override
any value without editing the file using the `HONEYPOT__SECTION__KEY`
environment variable convention (double underscore separated, matching
`docker-compose.yml`'s usage):

```bash
export HONEYPOT__DASHBOARD__PORT=8080
export HONEYPOT__SERVICES__SSH__PORT=2200
```

## Security notes (read before exposing this to the internet)

- **Change the dashboard password.** Generate a hash and put it in
  `config.yaml` (`dashboard.password_hash`) or the `DASHBOARD_PASSWORD_HASH`
  env var:
  ```bash
  python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('yourpassword'))"
  ```
- **Change `dashboard.secret_key`** to a random 32-byte value — never
  ship the placeholder.
- **Run honeypot listener ports as low-privilege**, or use Docker's
  `cap_add: NET_BIND_SERVICE` (already configured in `docker-compose.yml`)
  instead of running the whole process as root.
- **Put the dashboard behind TLS** (nginx reverse proxy, scaffold
  included but commented out in `docker-compose.yml`) before exposing
  it past a trusted internal network.
- This is a honeypot: assume anything it captures (uploaded files,
  attacker payloads) is hostile. Malware samples are saved but never
  executed (`malware_capture.py`); `is_quarantined=True` by default in
  the database.
- Decoy service ports default to >1024 (3306, 6379, 2525, 5353, 8443,
  8081, 9200) so the container doesn't need root for them; remap to
  privileged equivalents (53, 443, 25) only if you understand the
  exposure trade-off.

## Database schema

Six tables (`database.py`): `attack_events` (every connection/command),
`alerts` (severity-classified detections from `alert_system`),
`ip_intel` (cached GeoIP/ASN/abuse-score per IP), `sessions` (full SSH/FTP
session transcripts), `mitre_events` (ATT&CK technique mappings),
`malware_samples` (hashes, YARA matches, file type for every captured
upload). SQLite by default (zero-ops, fine for single-node); swap
`database.url` to a `postgresql://` DSN for multi-writer / larger
deployments — the schema is engine-agnostic.

## STIX export

```bash
python run.py --export-stix
# or via the dashboard: "STIX Export" button, or POST /api/export/stix
```

Produces a TLP-marked STIX 2.1 bundle (`exports/stix_bundle_*.json`)
containing `indicator` objects for malicious IPs and malware hashes,
`attack-pattern` objects for observed MITRE techniques, `relationship`
objects linking them, and a summary `report` object — ready to push to
a TAXII 2.1 server or attach to a CERT advisory.

## Testing

```bash
pytest tests/ -v --cov=. --cov-report=html
```

29 tests across the database layer, YARA detection (webshells, Log4Shell,
SQLi, reverse shells), STIX bundle structure, and config loading with
environment-variable overrides.

## Infrastructure hardening (v1.1)

A separate hardening pass added network segregation, systemd/container
security contexts, RBAC/IAM, secrets management, centralized logging with
WORM archival, IDS rules, automated malware analysis, signed CI releases,
and an SSH tarpit. See **`hardening/README.md`** for the full breakdown —
critically, for which pieces were actually tested end-to-end in this
environment versus reviewed-but-unverified against live infrastructure
(no K8s cluster, Vault server, AWS account, or ELK stack was available to
test against; that document says exactly which is which, file by file).

## Project layout

```
config.yaml            Master configuration
config_loader.py        YAML + ENV override loader
database.py              SQLAlchemy models + query helpers
yara_scanner.py          YARA rule engine (18 built-in rules)
stix_export.py           STIX 2.1 bundle builder
web_dashboard.py         Flask + SocketIO dashboard and REST API
run.py                   Entry point — orchestrates services + DB + dashboard
ssh_honeypot.py           [original] paramiko-based fake SSH shell
http_honeypot.py          [original] fake admin portal, SQLi/upload traps
ftp_honeypot.py           [original] fake filesystem over FTP
decoy_services.py         [original] MySQL/Redis/SMTP/DNS/HTTPS/ES banners
mitre_attack.py           [original, gap-fixed] ATT&CK technique mapping
alert_system.py           [original] severity-classified alert engine
logger.py                 [original] structured JSON event logger
tests/test_core.py        pytest suite for the new modules
Dockerfile / docker-compose.yml   Container deployment
.github/workflows/ci.yml          GitHub Actions pipeline
```

## Known limitations / honest caveats

- `database.py`'s `AttackEvent.country`/`asn` are populated from the
  offline IP-range heuristic in `logger.py`'s `_geoip()`, not a full
  MaxMind GeoIP2 database — accurate for major hosting ranges, not
  precise for residential ISPs. Swap in `geoip2` + a `.mmdb` file for
  production-grade geolocation (dependency already commented in
  `requirements.txt`).
- `ip_enrichment.py`'s async enrichment writes to `cache/ip_cache.json`
  rather than the new `ip_intel` SQL table — they're not yet unified.
  Bridging that is a natural next step if you extend this further.
- The Flask dev server runs with `allow_unsafe_werkzeug=True` for
  simplicity; put it behind the nginx/TLS scaffold in
  `docker-compose.yml` for anything beyond a lab/internal network.
- `docker_sandbox.py` (Cowrie-in-Docker session isolation) requires the
  `docker` Python package and a mounted Docker socket — disabled by
  default in `config.yaml` (`sandbox.enabled: false`) since it needs
  privileged access most CI/cloud environments won't grant by default.

## License / usage

Authorized research, education, and defensive security use only. Do not
deploy against systems or networks you don't own or have explicit
permission to monitor.
