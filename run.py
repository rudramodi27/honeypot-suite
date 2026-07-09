"""
run.py — Unified Entry Point (Headless + Web Dashboard)
Replaces main.py tkinter GUI with a proper deployable runner.

Modes:
  python run.py                  → start all services + web dashboard
  python run.py --no-dashboard   → headless mode (services only)
  python run.py --dashboard-only → web dashboard only (no new services)
  python run.py --init-db        → initialize database and exit
  python run.py --export-stix    → export STIX bundle and exit

Deploy:
  docker-compose up -d
  OR: python run.py
  Then: http://localhost:5000
"""

import argparse
import logging
import os
import sys
import signal
import threading
import time
from datetime import datetime
import tz_utils
import ip_enrichment as _ip_enrich

# ── Logging setup (before imports) ──────────────────────────
try:
    from config_loader import cfg
    log_level = getattr(logging, cfg.get("logging.level", "INFO"))
    log_dir   = cfg.get("logging.log_dir", "logs/")
except Exception:
    log_level = logging.INFO
    log_dir   = "logs/"

os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(log_dir, "honeypot_master.log")),
    ]
)
logger = logging.getLogger("HoneypotSuite")

# ── Banner ──────────────────────────────────────────────────
BANNER = r"""
  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝
                              S U I T E  v2.0
"""


def print_banner():
    print("\033[36m" + BANNER + "\033[0m")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python:  {sys.version.split()[0]}")
    try:
        from config_loader import cfg
        print(f"  Config:  config.yaml loaded")
        print(f"  DB:      {cfg.get('database.url', 'sqlite:///honeypot.db')}")
    except Exception:
        pass
    print()


def start_all_services(cfg_obj=None):
    """
    Start all enabled honeypot services.

    NOTE: ssh_honeypot.start() / http_honeypot.start() / ftp_honeypot.start() /
    decoy_services.start() are ALL non-blocking — each spins up its own
    internal daemon thread (socket accept loop) and returns immediately.
    We call them directly on the main thread; no extra wrapping needed.
    Only import/bind errors are caught here.
    """
    started = []

    def _enabled(key, default=True):
        return cfg_obj.get(key, default) if cfg_obj else default

    # ── SSH honeypot ──────────────────────────────────────────
    if _enabled("services.ssh.enabled", True):
        try:
            import ssh_honeypot
            port = cfg_obj.get("services.ssh.port", 2222) if cfg_obj else 2222
            ssh_honeypot.start(port=port)
            started.append(("SSH", port))
        except Exception as e:
            logger.warning(f"SSH honeypot failed to start: {e}")

    # ── HTTP honeypot ─────────────────────────────────────────
    if _enabled("services.http.enabled", True):
        try:
            import http_honeypot
            port = cfg_obj.get("services.http.port", 8080) if cfg_obj else 8080
            http_honeypot.start(port=port)
            started.append(("HTTP", port))
        except Exception as e:
            logger.warning(f"HTTP honeypot failed to start: {e}")

    # ── FTP honeypot ──────────────────────────────────────────
    if _enabled("services.ftp.enabled", True):
        try:
            import ftp_honeypot
            port = cfg_obj.get("services.ftp.port", 2121) if cfg_obj else 2121
            ftp_honeypot.start(port=port)
            started.append(("FTP", port))
        except Exception as e:
            logger.warning(f"FTP honeypot failed to start: {e}")

    # ── Decoy services (MySQL/Redis/SMTP/DNS/HTTPS/Admin/ES) ──
    if _enabled("services.decoys.mysql.enabled", True):
        try:
            import decoy_services
            kw = dict(
                mysql_port = cfg_obj.get("services.decoys.mysql.port", 3306)   if cfg_obj else 3306,
                redis_port = cfg_obj.get("services.decoys.redis.port", 6379)   if cfg_obj else 6379,
                smtp_port  = cfg_obj.get("services.decoys.smtp.port", 2525)    if cfg_obj else 2525,
                dns_port   = cfg_obj.get("services.decoys.dns.port", 5353)    if cfg_obj else 5353,
                https_port = cfg_obj.get("services.decoys.https.port", 8443)  if cfg_obj else 8443,
                admin_port = cfg_obj.get("services.decoys.admin_panel.port", 8081) if cfg_obj else 8081,
                es_port    = cfg_obj.get("services.decoys.elasticsearch.port", 9200) if cfg_obj else 9200,
            )
            decoy_services.start(**kw)
            started.append(("Decoys", kw))
        except Exception as e:
            logger.warning(f"Decoy services failed to start: {e}")

    # ── YARA scanner (init/compile rules) ──────────────────────
    try:
        from yara_scanner import get_scanner
        get_scanner()
        started.append(("YARA", "rules compiled"))
    except Exception as e:
        logger.warning(f"YARA scanner not available: {e}")

    # mitre_attack and alert_system are stateless modules — they
    # work as soon as they're imported (which logger.py already does
    # internally). No explicit init call exists or is needed.

    for name, info in started:
        logger.info(f"[OK] {name} -> {info}")

    return started


def _severity_for_event(event_name: str) -> str:
    """
    Classify AttackEvent.severity from the event name logger.log() actually
    receives (NOT alert_system's alert_type vocabulary — those are two
    different namespaces). Built from the real event strings emitted by
    ssh_honeypot.py, http_honeypot.py, ftp_honeypot.py, decoy_services.py:

      SSH:   SSH_AUTH_ATTEMPT/SUCCESS/FAILURE, SSH_CONNECT/DISCONNECT,
             SSH_COMMAND, SSH_EXEC, SSH_ERROR, SSH_SESSION_STATS, SSH_START
      HTTP:  GET, LOGIN_ATTEMPT/SUCCESS/FAILURE, SQLI_ATTEMPT, BAIT_ACCESS,
             SEARCH, USER_LOOKUP, DB_ACCESS, LOGS_ACCESS, EXPORT_ATTEMPT,
             USERNAME_ENTERED, FILE_UPLOAD, MALICIOUS_UPLOAD, HTTP_START
      FTP:   USER, PASS, AUTH_SUCCESS[_ANON], AUTH_FAILURE, CWD, LIST,
             RETR_ATTEMPT/PARTIAL, STOR_ATTEMPT/COMPLETE, DELE_ATTEMPT,
             QUIT, CONNECT, DISCONNECT, CMD_<verb>, SESSION_ERROR, FTP_START
      Decoy: DECOY_<SVC>_START, DNS_QUERY_UDP

    Exact matches take priority; an event-name-keyword fallback covers
    the dynamic ones (CMD_LIST, DECOY_REDIS_START, etc.) without needing
    every literal enumerated.
    """
    e = (event_name or "").upper()

    exact = {
        "MALICIOUS_UPLOAD":  "CRITICAL",
        "SQLI_ATTEMPT":      "HIGH",
        "LOGIN_FAILURE":     "HIGH",
        "SSH_AUTH_FAILURE":  "HIGH",
        "AUTH_FAILURE":      "HIGH",
        "BAIT_ACCESS":       "HIGH",
        "DELE_ATTEMPT":      "HIGH",
        "STOR_ATTEMPT":      "HIGH",        # file upload attempt — possible webshell
        "LOGIN_SUCCESS":     "MEDIUM",
        "LOGIN_ATTEMPT":     "MEDIUM",
        "SSH_AUTH_SUCCESS":  "MEDIUM",
        "SSH_AUTH_ATTEMPT":  "MEDIUM",
        "SSH_COMMAND":       "MEDIUM",
        "SSH_EXEC":          "MEDIUM",
        "AUTH_SUCCESS":      "MEDIUM",
        "AUTH_SUCCESS_ANON": "MEDIUM",
        "RETR_ATTEMPT":      "MEDIUM",
        "RETR_PARTIAL":      "MEDIUM",
        "STOR_COMPLETE":     "MEDIUM",
        "FILE_UPLOAD":       "MEDIUM",
        "SEARCH":            "MEDIUM",
        "USER_LOOKUP":       "MEDIUM",
        "DB_ACCESS":         "MEDIUM",
        "LOGS_ACCESS":       "MEDIUM",
        "EXPORT_ATTEMPT":    "MEDIUM",
        "USERNAME_ENTERED":  "LOW",
        "GET":               "LOW",
        "CONNECT":           "LOW",
        "SSH_CONNECT":       "LOW",
        "SSH_DISCONNECT":    "LOW",
        "DISCONNECT":        "LOW",
        "QUIT":              "LOW",
        "USER":              "LOW",
        "PASS":              "LOW",
        "CWD":               "LOW",
        "LIST":              "LOW",
        "SESSION_ERROR":     "LOW",
        "SSH_ERROR":         "LOW",
        "SSH_SESSION_STATS": "LOW",
        "SESSION_RECORDED":  "LOW",
        "DNS_QUERY_UDP":     "LOW",
    }
    if e in exact:
        return exact[e]

    # Dynamic names: CMD_<FTP-VERB>, DECOY_<SERVICE>_START, *_START, etc.
    if e.endswith("_START"):
        return "LOW"
    if "MALICIOUS" in e or "WEBSHELL" in e or "EXPLOIT" in e:
        return "CRITICAL"
    if "FAILURE" in e or "SQLI" in e or "BAIT" in e:
        return "HIGH"
    if "ATTEMPT" in e or "CMD_" in e or "UPLOAD" in e:
        return "MEDIUM"
    return "LOW"


def _patch_existing_modules():
    """
    Monkey-patch the THREE actual integration points in the existing
    codebase so events flow into the new SQLite DB and the live web
    dashboard, without touching the original honeypot service files:

      1. logger.log(event, ip, service, sid="", port=0, **kwargs)
         → every connection/command/login attempt. Returns the entry dict.
      2. alert_system.trigger(alert_type, ip, service, detail="", sid="", **extra)
         → severity-classified security alerts.
      3. mitre_attack.map_and_log(event: dict) -> list[dict]
         → MITRE ATT&CK technique mappings derived from each logged event.

    Field names below intentionally mirror the ACTUAL dicts these
    functions already produce (ip/event/port — not src_ip/event_type/
    dst_port) to avoid silently losing data on a name mismatch.
    """
    try:
        from database import DbSession, AttackEvent, Alert, MitreEvent
    except Exception as e:
        logger.warning(f"Database layer unavailable, skipping patch: {e}")
        return

    try:
        from web_dashboard import push_event
    except Exception:
        def push_event(_): pass  # dashboard optional

    # ── 1. Patch logger.log() ──────────────────────────────────
    try:
        import logger as hp_log
        _original_log = hp_log.log

        def _persist_geo(event_id: int, ip: str):
            """
            Async callback: fetch real geolocation for a public IP (city,
            lat/lon, country — via the existing ip_enrichment module, which
            already correctly skips private/local addresses) and persist it
            to IPIntel + backfill the originating AttackEvent's city field.
            Never touches private IPs — those keep the 'Local/Private'
            label already set by logger.py's synchronous _geoip().
            """
            try:
                import ip_enrichment as _ip_enrich
                if _ip_enrich._is_private(ip):
                    return
                geo = _ip_enrich.enrich(ip)  # cached after first lookup per IP
            except Exception:
                return
            try:
                from database import DbSession, AttackEvent, IPIntel
                with DbSession() as s:
                    row = s.query(IPIntel).filter(IPIntel.ip == ip).first()
                    if row is None:
                        row = IPIntel(ip=ip)
                        s.add(row)
                    row.country      = geo.get("country") or row.country
                    row.country_code = geo.get("country_code") or row.country_code
                    row.city         = geo.get("city") or row.city
                    row.region       = geo.get("region") or row.region
                    row.latitude     = geo.get("lat") if geo.get("lat") else row.latitude
                    row.longitude    = geo.get("lon") if geo.get("lon") else row.longitude
                    row.org          = geo.get("org") or row.org
                    row.asn          = geo.get("asn") or row.asn
                    row.isp          = geo.get("isp") or row.isp
                    row.is_tor       = geo.get("threat_type") == "tor_exit"
                    row.is_datacenter= geo.get("threat_type") == "datacenter"
                    row.is_scanner   = geo.get("threat_type") == "scanner"
                    row.threat_label = geo.get("threat_label") or row.threat_label
                    row.total_hits   = (row.total_hits or 0) + 1
                    row.raw_intel    = geo

                    ev = s.query(AttackEvent).filter(AttackEvent.id == event_id).first()
                    if ev and geo.get("city"):
                        ev.city = geo["city"]
                        if geo.get("country"):
                            ev.country = geo["country"]
                    s.commit()
            except Exception:
                pass  # never let enrichment persistence break the honeypot

        def patched_log(event: str, ip: str, service: str, sid: str = "",
                        port: int = 0, **kwargs):
            entry = _original_log(event, ip, service, sid=sid, port=port, **kwargs)
            try:
                with DbSession() as s:
                    row = AttackEvent(
                        service     = service,
                        src_ip      = ip,
                        dst_port    = port,
                        event_type  = event,
                        username    = kwargs.get("username"),
                        password    = kwargs.get("password"),
                        command     = kwargs.get("command"),
                        url_path    = kwargs.get("path"),
                        user_agent  = kwargs.get("user_agent"),
                        payload     = kwargs.get("payload"),
                        severity    = _severity_for_event(event),
                        country     = entry.get("country"),
                        asn         = entry.get("asn"),
                        session_id  = sid or None,
                        raw_log     = entry,
                    )
                    s.add(row)
                    s.commit()
                    event_id = row.id
                # ── Map coordinates for the live feed (rendering only) ──
                # Private/local IPs: fixed, clearly-labeled dev point.
                # Public IPs: use whatever IPIntel already has cached from
                # a prior sighting; if this is the very first sighting,
                # the async lookup above will populate it for the next
                # periodic map refresh (no coordinates are invented here).
                map_lat = map_lng = None
                map_is_dev = False
                map_country = entry.get("country")
                map_city = None
                try:
                    if _ip_enrich._is_private(ip):
                        dc = cfg.get("display.dev_coordinates",
                                     {"lat": 23.0225, "lng": 72.5714, "label": "Local Test Environment"})
                        map_lat, map_lng = dc["lat"], dc["lng"]
                        map_is_dev = True
                        map_country = dc.get("label", "Local Test Environment")
                    else:
                        with DbSession() as s2:
                            existing = s2.query(IPIntel).filter(IPIntel.ip == ip).first()
                            if existing and existing.latitude and existing.longitude:
                                map_lat, map_lng = existing.latitude, existing.longitude
                                map_country = existing.country or map_country
                                map_city = existing.city
                except Exception:
                    pass

                push_event({
                    "src_ip": ip, "service": service, "event_type": event,
                    "username": kwargs.get("username"),
                    "severity": _severity_for_event(event),
                    "lat": map_lat, "lng": map_lng,
                    "is_dev": map_is_dev, "country": map_country, "city": map_city,
                    "timestamp_local": tz_utils.local_isoformat(datetime.utcnow()),
                })
                # Non-blocking: real geolocation for public IPs only.
                # Private/local addresses are left as "Local/Private" (unchanged).
                if ip and not ip.startswith(("10.", "192.168.", "127.", "172.16.",
                                              "172.17.", "172.18.", "172.19.", "172.20.")):
                    threading.Thread(target=_persist_geo, args=(event_id, ip), daemon=True).start()
            except Exception:
                pass  # never let telemetry break the honeypot itself
            return entry

        hp_log.log = patched_log
        logger.info("[OK] logger.log() patched -> AttackEvent table + live feed")
    except Exception as e:
        logger.warning(f"Could not patch logger.log: {e}")

    # ── 2. Patch alert_system.trigger() ────────────────────────
    try:
        import alert_system
        _original_trigger = alert_system.trigger

        def patched_trigger(alert_type: str, ip: str, service: str,
                            detail: str = "", sid: str = "", **extra):
            alert = _original_trigger(alert_type, ip, service, detail=detail, sid=sid, **extra)
            try:
                with DbSession() as s:
                    s.add(Alert(
                        severity    = alert.get("severity", "MEDIUM"),
                        alert_type  = alert_type,
                        src_ip      = ip,
                        service     = service,
                        description = detail,
                        details     = alert,
                    ))
                    s.commit()
                push_event({
                    "src_ip": ip, "service": service,
                    "event_type": f"ALERT:{alert_type}",
                    "severity": alert.get("severity", "MEDIUM"),
                })
            except Exception:
                pass
            return alert

        alert_system.trigger = patched_trigger
        logger.info("[OK] alert_system.trigger() patched -> Alert table + live feed")
    except Exception as e:
        logger.warning(f"Could not patch alert_system.trigger: {e}")

    # ── 3. Patch mitre_attack.map_and_log() ────────────────────
    try:
        import mitre_attack
        _original_map_and_log = mitre_attack.map_and_log

        def patched_map_and_log(event: dict):
            techniques = _original_map_and_log(event)
            if techniques:
                try:
                    with DbSession() as s:
                        for t in techniques:
                            s.add(MitreEvent(
                                src_ip        = t.get("ip", ""),
                                service       = t.get("service", ""),
                                tactic        = t.get("tactic", ""),
                                tactic_id     = t.get("tactic_id", ""),
                                technique     = t.get("technique", ""),
                                technique_id  = t.get("id", ""),
                                confidence    = t.get("confidence", ""),
                                description   = t.get("description", ""),
                                raw_event     = t,
                            ))
                        s.commit()
                except Exception:
                    pass
            return techniques

        mitre_attack.map_and_log = patched_map_and_log
        logger.info("[OK] mitre_attack.map_and_log() patched -> MitreEvent table")
    except Exception as e:
        logger.warning(f"Could not patch mitre_attack.map_and_log: {e}")

    # ── 4. SSH tarpit (hardening/tarpit.py) ─────────────────────
    # Independent of the database-routing patches above — engages
    # purely from config.yaml's deception.* settings, no DB required.
    try:
        from hardening.tarpit import patch_ssh_honeypot
        patch_ssh_honeypot()
    except Exception as e:
        logger.warning(f"Could not patch SSH tarpit: {e}")


# ── Graceful shutdown ────────────────────────────────────────
_shutdown_event = threading.Event()

def _handle_signal(signum, frame):
    logger.info(f"Received signal {signum} — shutting down gracefully...")
    _shutdown_event.set()

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Main ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Advanced Honeypot Suite v2.0")
    parser.add_argument("--no-dashboard",   action="store_true", help="Headless mode")
    parser.add_argument("--dashboard-only", action="store_true", help="Dashboard only")
    parser.add_argument("--init-db",        action="store_true", help="Init DB and exit")
    parser.add_argument("--export-stix",    action="store_true", help="Export STIX and exit")
    parser.add_argument("--debug",          action="store_true", help="Debug mode")
    args = parser.parse_args()

    print_banner()

    # ── Init DB ───────────────────────────────────────────────
    try:
        from database import init_db
        init_db()
        logger.info("[OK] Database ready")
    except Exception as e:
        logger.error(f"Database init failed: {e}")

    if args.init_db:
        logger.info("Database initialized. Exiting.")
        return

    # ── STIX export ───────────────────────────────────────────
    if args.export_stix:
        try:
            from stix_export import StixExporter
            path = StixExporter().export_from_db(hours=24)
            logger.info(f"STIX bundle exported: {path}")
        except Exception as e:
            logger.error(f"STIX export failed: {e}")
        return

    # ── Load config ───────────────────────────────────────────
    cfg_obj = None
    try:
        from config_loader import cfg as _cfg
        cfg_obj = _cfg
    except Exception:
        pass

    # ── Patch event pipeline ──────────────────────────────────
    if not args.dashboard_only:
        _patch_existing_modules()

    # ── Start honeypot services ───────────────────────────────
    service_threads = []
    if not args.dashboard_only:
        service_threads = start_all_services(cfg_obj)
        time.sleep(1.0)          # Give services time to bind ports

    # ── Status summary ────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  HoneypotSuite v2.0 — All systems active")
    logger.info("=" * 60)
    if not args.no_dashboard:
        host = cfg_obj.get("dashboard.host", "0.0.0.0") if cfg_obj else "0.0.0.0"
        port = cfg_obj.get("dashboard.port", 5000) if cfg_obj else 5000
        logger.info(f"  Dashboard: http://localhost:{port}")
    logger.info(f"  Logs:      {log_dir}")
    logger.info("  Press Ctrl+C to stop")
    logger.info("=" * 60)

    # ── Start web dashboard ───────────────────────────────────
    if not args.no_dashboard:
        try:
            from web_dashboard import run_dashboard
            # Run dashboard in main thread (SocketIO requires this)
            run_dashboard(debug=args.debug)
        except ImportError as e:
            logger.error(f"Web dashboard not available: {e}")
            logger.info("Install with: pip install flask flask-socketio")
            # Fall back to blocking wait
            _shutdown_event.wait()
    else:
        logger.info("Headless mode — dashboard disabled")
        _shutdown_event.wait()

    logger.info("HoneypotSuite shutdown complete.")


if __name__ == "__main__":
    main()
