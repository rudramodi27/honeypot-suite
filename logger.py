"""
logger.py — Centralized Honeypot Intelligence Logger
Handles: structured JSON logging, session management,
         scanner detection, GeoIP lookup, CSV/JSON export,
         per-attacker session files, threat analytics
"""

import json
import os
import csv
import re
import time
import hashlib
import secrets
import threading
import socket
from datetime import datetime
from collections import defaultdict
try:
    import ip_enrichment as _ip_enrich
    _ENRICH_OK = True
except ImportError: _ENRICH_OK = False
try:
    import mitre_attack as _mitre
    _MITRE_OK = True
except ImportError: _MITRE_OK = False

# ── Directories ───────────────────────────────────────────────────────────────
os.makedirs("logs",    exist_ok=True)
os.makedirs("attacks", exist_ok=True)
os.makedirs("exports", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

# ── Master log file ───────────────────────────────────────────────────────────
MASTER_LOG = "logs/honeypot_master.log"

# ── Known scanner signatures ──────────────────────────────────────────────────
SCANNER_UA = [
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "dirbuster",
    "dirsearch", "gobuster", "wfuzz", "hydra", "medusa", "burp",
    "nessus", "openvas", "acunetix", "nuclei", "metasploit",
    "python-requests", "go-http-client", "curl/", "wget/",
    "libwww-perl", "scrapy", "zgrab", "shodan", "censys",
]

SCANNER_PAYLOADS = [
    "' OR 1=1", "UNION SELECT", "../../etc", "../etc/passwd",
    "<script>", "<?php", "cmd.exe", "/bin/sh", "base64_decode",
    "eval(", "exec(", "system(", "passthru(", "shell_exec(",
    "../../../../", "%2e%2e%2f", "%00", "null byte",
    "1=1--", "or 1=1", "drop table", "insert into",
]

MALICIOUS_FILES = [
    "shell.php", "cmd.php", "c99.php", "r57.php", "webshell",
    "backdoor", ".php", ".asp", ".aspx", ".jsp", ".exe",
    ".bat", ".sh", ".py", ".pl",
]

# ── In-memory analytics store ─────────────────────────────────────────────────
_lock = threading.Lock()

_analytics = {
    "total_connections": 0,
    "ip_counts":         defaultdict(int),
    "password_attempts": defaultdict(int),
    "username_attempts": defaultdict(int),
    "commands_used":     defaultdict(int),
    "scanners_detected": defaultdict(int),
    "service_counts":    defaultdict(int),
    "country_counts":    defaultdict(int),
    "active_sessions":   {},          # session_id -> info dict
    "ip_intel":          {},          # ip -> enrichment data
    "recent_events":     [],          # last 200 events
}

# ── GeoIP (lightweight offline fallback) ──────────────────────────────────────
_geo_cache = {}

def _geoip(ip: str) -> dict:
    """Best-effort country lookup — purely from IP ranges (no external calls)."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Private / loopback ranges
    private = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.20.", "127.", "0.", "::1"]
    for p in private:
        if ip.startswith(p):
            result = {"country": "Local/Private", "asn": "Private Network"}
            _geo_cache[ip] = result
            return result

    # Rough heuristic from first octet — just for demo realism
    try:
        first = int(ip.split(".")[0])
        mapping = {
            range(1,   50):  ("United States",  "ARIN"),
            range(50,  80):  ("Europe",          "RIPE"),
            range(80,  100): ("Asia Pacific",    "APNIC"),
            range(100, 130): ("Latin America",   "LACNIC"),
            range(130, 160): ("Africa",          "AFRINIC"),
            range(160, 200): ("Russia/CIS",      "RIPE"),
            range(200, 256): ("China/Asia",      "APNIC"),
        }
        for r, (country, asn) in mapping.items():
            if first in r:
                result = {"country": country, "asn": asn}
                _geo_cache[ip] = result
                return result
    except Exception:
        pass

    result = {"country": "Unknown", "asn": "Unknown"}
    _geo_cache[ip] = result
    return result


# ── Session management ────────────────────────────────────────────────────────
def new_session(ip: str, service: str) -> str:
    sid = secrets.token_hex(8)
    geo = _geoip(ip)
    with _lock:
        _analytics["active_sessions"][sid] = {
            "ip": ip, "service": service,
            "country": geo["country"], "asn": geo["asn"],
            "start": datetime.now().isoformat(),
            "events": [], "commands": [],
            "credentials": [], "payloads": [],
            "files_uploaded": [], "tools_detected": [],
        }
        _analytics["total_connections"] += 1
        _analytics["ip_counts"][ip] += 1
        _analytics["service_counts"][service] += 1
        _analytics["country_counts"][geo["country"]] += 1
    return sid


def end_session(sid: str):
    with _lock:
        sess = _analytics["active_sessions"].pop(sid, None)
    if sess:
        sess["end"] = datetime.now().isoformat()
        # Write per-attacker file
        ip_safe = sess["ip"].replace(".", "_")
        path = f"attacks/{ip_safe}_{sid}.json"
        try:
            with open(path, "w") as f:
                json.dump(sess, f, indent=2)
        except Exception:
            pass


# ── Core logging function ─────────────────────────────────────────────────────
def log(event: str, ip: str, service: str, sid: str = "",
        port: int = 0, **kwargs) -> dict:

    geo   = _geoip(ip)
    entry = {
        "timestamp":  datetime.now().isoformat(),
        "ip":         ip,
        "port":       port,
        "service":    service,
        "event":      event,
        "session_id": sid,
        "country":    geo["country"],
        "asn":        geo["asn"],
    }
    entry.update({k: v for k, v in kwargs.items() if v not in (None, "", {}, [])})

    # Async IP enrichment (non-blocking)
    if _ENRICH_OK and ip and not ip.startswith(('10.','192.168.','127.')):
        def _enrich_cb(enriched_ip, data):
            with _lock:
                if enriched_ip in _analytics.get('ip_intel', {}):
                    return
                _analytics.setdefault('ip_intel', {})[enriched_ip] = data
        _ip_enrich.enrich_async(ip, _enrich_cb)

    # Async MITRE mapping
    if _MITRE_OK:
        threading.Thread(target=_mitre.map_and_log,
                         args=(entry,), daemon=True).start()

    # Write to master log
    try:
        with open(MASTER_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # Service-specific log
    svc_log = f"logs/{service.lower()}_honeypot.log"
    try:
        with open(svc_log, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # Update analytics
    with _lock:
        if "username" in kwargs:
            _analytics["username_attempts"][kwargs["username"]] += 1
        if "password" in kwargs:
            _analytics["password_attempts"][kwargs["password"]] += 1
        if "command" in kwargs:
            _analytics["commands_used"][kwargs["command"].split()[0]] += 1
        if sid and sid in _analytics["active_sessions"]:
            sess = _analytics["active_sessions"][sid]
            sess["events"].append(event)
            if "command" in kwargs:
                sess["commands"].append(kwargs["command"])
            if "username" in kwargs and "password" in kwargs:
                cred = (kwargs["username"], kwargs["password"])
                if cred not in sess["credentials"]:
                    sess["credentials"].append(cred)
            if "payload" in kwargs:
                sess["payloads"].append(kwargs["payload"])
            if "filename" in kwargs:
                sess["files_uploaded"].append(kwargs["filename"])
            if "tool" in kwargs:
                t = kwargs["tool"]
                sess["tools_detected"].append(t)
                _analytics["scanners_detected"][t] += 1

        # Keep recent 200 events
        _analytics["recent_events"].append(entry)
        if len(_analytics["recent_events"]) > 200:
            _analytics["recent_events"].pop(0)

    return entry


# ── Scanner / tool detection ──────────────────────────────────────────────────
def detect_scanner(user_agent: str = "", path: str = "",
                   payload: str = "") -> str | None:
    ua_low = (user_agent or "").lower()
    for sig in SCANNER_UA:
        if sig in ua_low:
            return sig

    path_low = (path or "").lower()
    for sig in ["nikto", "sqlmap", "nmap", ".env", "wp-login",
                "phpmyadmin", "phpinfo", "xmlrpc", ".git/"]:
        if sig in path_low:
            return sig

    pay_low = (payload or "").lower()
    for sig in SCANNER_PAYLOADS:
        if sig.lower() in pay_low:
            return "payload_injection"

    return None


def detect_malicious_file(filename: str) -> bool:
    fn = filename.lower()
    return any(sig in fn for sig in MALICIOUS_FILES)


# ── Analytics getters ─────────────────────────────────────────────────────────
def get_analytics() -> dict:
    with _lock:
        return {
            "total_connections": _analytics["total_connections"],
            "top_ips":           sorted(_analytics["ip_counts"].items(),
                                        key=lambda x: x[1], reverse=True)[:10],
            "top_passwords":     sorted(_analytics["password_attempts"].items(),
                                        key=lambda x: x[1], reverse=True)[:10],
            "top_usernames":     sorted(_analytics["username_attempts"].items(),
                                        key=lambda x: x[1], reverse=True)[:10],
            "top_commands":      sorted(_analytics["commands_used"].items(),
                                        key=lambda x: x[1], reverse=True)[:10],
            "scanners":          dict(_analytics["scanners_detected"]),
            "services":          dict(_analytics["service_counts"]),
            "countries":         sorted(_analytics["country_counts"].items(),
                                        key=lambda x: x[1], reverse=True)[:10],
            "active_sessions":   len(_analytics["active_sessions"]),
            "active_list":       list(_analytics["active_sessions"].values()),
            "recent_events":     list(_analytics["recent_events"])[-50:],
            "ip_intel":          dict(_analytics.get("ip_intel", {})),
        }


# ── Export functions ──────────────────────────────────────────────────────────
def export_json(path: str = "exports/threat_intel.json"):
    data = get_analytics()
    # Also include all master log entries
    entries = []
    try:
        with open(MASTER_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except FileNotFoundError:
        pass
    data["all_events"] = entries
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def export_csv(path: str = "exports/threat_intel.csv"):
    fields = ["timestamp", "ip", "port", "service", "event",
              "username", "password", "command", "payload",
              "filename", "country", "asn", "session_id"]
    rows = []
    try:
        with open(MASTER_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
    except FileNotFoundError:
        pass

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return path