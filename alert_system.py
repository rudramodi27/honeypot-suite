"""
alert_system.py — Deception Alert System
Triggers immediately when attacker accesses bait files/endpoints.

Alert types:
  BAIT_FILE_ACCESS  — attacker opened /backup/users_dump.sql etc.
  CREDENTIAL_TRAP   — attacker used honeypot credentials on other services
  WEBSHELL_UPLOAD   — attacker uploaded shell.php / cmd.php
  SQLI_ATTEMPT      — SQL injection payload detected
  SCANNER_DETECTED  — automated tool detected (nikto, sqlmap etc.)
  BRUTE_FORCE       — >5 failed logins from same IP
  SSH_BAIT_FILE     — attacker read /home/admin/backup_creds.txt etc.
  FTP_DOWNLOAD_BAIT — attacker tried to download bait file via FTP

Each alert:
  - Logs to alerts/alerts.log (JSON)
  - Shows GUI popup (non-blocking)
  - Plays system beep (optional)
  - Updates GUI dashboard counter
"""

import os, json, threading, time, queue
from datetime import datetime
from collections import defaultdict
try:
    import notifier as _notifier
    _NOTIFIER_OK = True
except ImportError:
    _NOTIFIER_OK = False

os.makedirs("alerts", exist_ok=True)

ALERT_LOG = "alerts/alerts.log"

# ── Severity levels ────────────────────────────────────────────────────────────
SEVERITY = {
    "BAIT_FILE_ACCESS":   "HIGH",
    "CREDENTIAL_TRAP":    "CRITICAL",
    "WEBSHELL_UPLOAD":    "CRITICAL",
    "SQLI_ATTEMPT":       "MEDIUM",
    "SCANNER_DETECTED":   "LOW",
    "BRUTE_FORCE":        "HIGH",
    "SSH_BAIT_FILE":      "HIGH",
    "FTP_DOWNLOAD_BAIT":  "HIGH",
    "MALICIOUS_UPLOAD":   "CRITICAL",
    "DNS_RECON":          "LOW",
    "ES_AUTH_ATTEMPT":    "MEDIUM",
    "REDIS_AUTH_ATTEMPT": "MEDIUM",
}

SEV_COLOR = {
    "LOW":      "#ffab40",
    "MEDIUM":   "#ff8c00",
    "HIGH":     "#ff3c5a",
    "CRITICAL": "#cc0000",
}

SEV_EMOJI = {
    "LOW":      "🔵",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}

# ── Brute force tracker ────────────────────────────────────────────────────────
_fail_counts: dict = defaultdict(lambda: {"count": 0, "last": 0.0, "alerted": False})
try:
    from config_loader import cfg as _cfg
    BRUTE_THRESHOLD = _cfg.get("alerting.brute_force_threshold", 5)
    BRUTE_WINDOW    = _cfg.get("alerting.brute_force_window_seconds", 120)
except Exception:
    BRUTE_THRESHOLD = 5
    BRUTE_WINDOW    = 120   # seconds

# ── Alert queue for GUI ────────────────────────────────────────────────────────
alert_queue: queue.Queue = queue.Queue()

# ── Callbacks registered by GUI ───────────────────────────────────────────────
_gui_callbacks: list = []

def register_gui_callback(fn):
    """GUI registers a function to call when alert fires."""
    _gui_callbacks.append(fn)


# ── Core alert function ────────────────────────────────────────────────────────
def trigger(alert_type: str, ip: str, service: str,
            detail: str = "", sid: str = "",
            **extra) -> dict:
    """
    Fire an alert. Thread-safe. Non-blocking.
    Returns the alert dict.
    """
    sev = SEVERITY.get(alert_type, "MEDIUM")
    alert = {
        "timestamp":  datetime.now().isoformat(),
        "type":       alert_type,
        "severity":   sev,
        "ip":         ip,
        "service":    service,
        "detail":     detail,
        "session_id": sid,
        **extra,
    }

    # 1. Write to log
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:
        pass

    # 2. Push to queue (GUI polls this)
    alert_queue.put(alert)

    # 3b. Send Telegram/Email notification
    if _NOTIFIER_OK:
        _notifier.notify(alert)

    # 3. Call GUI callbacks (non-blocking thread)
    for cb in _gui_callbacks:
        try:
            threading.Thread(target=cb, args=(alert,), daemon=True).start()
        except Exception:
            pass

    return alert


# ── Track failed logins for brute force detection ─────────────────────────────
def record_failed_login(ip: str, service: str, username: str, password: str):
    """Call on every AUTH_FAILURE. Auto-triggers BRUTE_FORCE alert."""
    rec = _fail_counts[ip]
    now = time.time()

    # Reset window if too old
    if now - rec["last"] > BRUTE_WINDOW:
        rec["count"]   = 0
        rec["alerted"] = False

    rec["count"] += 1
    rec["last"]   = now

    if rec["count"] >= BRUTE_THRESHOLD and not rec["alerted"]:
        rec["alerted"] = True
        trigger(
            "BRUTE_FORCE", ip, service,
            detail=f"{rec['count']} failed logins in {BRUTE_WINDOW}s "
                   f"(last: {username}/{password})",
            attempts=rec["count"],
            last_username=username,
            last_password=password,
        )


# ── Bait file list ─────────────────────────────────────────────────────────────
HTTP_BAIT_PATHS = {
    "/backup/users_dump.sql",
    "/backup/admin_credentials.xlsx",
    "/backup/backup_2024.sql",
    "/backup/lcf_ledger_backup.sql",
    "/backup/employee_records_2024.csv",
    "/config/db.php",
    "/config/database.yml",
    "/config/config.ini",
    "/private/notes.txt",
    "/db_dump/lcf_ledger_march2025.sql",
    "/admin_backup/portal_backup.zip",
    "/.env",
}

SSH_BAIT_FILES = {
    "/home/admin/backup_creds.txt",
    "/home/admin/.env",
    "/home/admin/database.yml",
    "/home/admin/config.ini",
    "/var/backups/passwd.bak",
    "/var/backups/shadow.bak",
    "/var/backups/lcf_ledger_backup.sql",
    "/root/.ssh/id_rsa",
    "/etc/shadow",
}

FTP_BAIT_FILES = {
    "lcf_ledger_backup.sql",
    "employee_records_2024.csv",
    "full_backup_2025.tar.gz",
    "password_backup.txt",
    ".env",
    "database.yml",
    "config.ini",
    "shadow.bak",
    "passwd.bak",
}

WEBSHELL_NAMES = {
    "shell.php", "cmd.php", "c99.php", "r57.php",
    "webshell.php", "backdoor.php", "b374k.php",
    "wso.php", "bypass.php", "upload.php",
}


def check_http_path(path: str, ip: str, sid: str = ""):
    """Call on every HTTP GET — checks if it's a bait path."""
    if path in HTTP_BAIT_PATHS:
        trigger("BAIT_FILE_ACCESS", ip, "HTTP",
                detail=f"Attacker accessed bait file: {path}",
                sid=sid, path=path)


def check_ssh_file(filepath: str, ip: str, sid: str = ""):
    """Call when attacker cats a file in SSH."""
    if filepath in SSH_BAIT_FILES:
        trigger("SSH_BAIT_FILE", ip, "SSH",
                detail=f"Attacker read sensitive file: {filepath}",
                sid=sid, filepath=filepath)


def check_ftp_retr(filename: str, ip: str, sid: str = ""):
    """Call on every FTP RETR attempt."""
    if filename in FTP_BAIT_FILES:
        trigger("FTP_DOWNLOAD_BAIT", ip, "FTP",
                detail=f"Attacker tried to download bait file: {filename}",
                sid=sid, filename=filename)


def check_upload(filename: str, ip: str, service: str, sid: str = ""):
    """Call on file upload — detects webshells."""
    name_lower = filename.lower()
    if any(ws in name_lower for ws in WEBSHELL_NAMES):
        trigger("WEBSHELL_UPLOAD", ip, service,
                detail=f"Webshell upload attempt: {filename}",
                sid=sid, filename=filename)


def check_sqli(payload: str, ip: str, sid: str = ""):
    """Call when SQL injection payload detected."""
    trigger("SQLI_ATTEMPT", ip, "HTTP",
            detail=f"SQLi payload: {payload[:100]}",
            sid=sid, payload=payload[:200])


def check_scanner(tool: str, ip: str, service: str, sid: str = ""):
    """Call when automated scanner detected."""
    trigger("SCANNER_DETECTED", ip, service,
            detail=f"Scanner detected: {tool}",
            sid=sid, tool=tool)


# ── Load alert history ─────────────────────────────────────────────────────────
def load_history(limit: int = 100) -> list[dict]:
    """Load recent alerts from log file."""
    alerts = []
    try:
        with open(ALERT_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except Exception:
                        pass
    except FileNotFoundError:
        pass
    return alerts[-limit:]


def get_stats() -> dict:
    """Return alert statistics."""
    history = load_history(500)
    by_type = defaultdict(int)
    by_sev  = defaultdict(int)
    by_ip   = defaultdict(int)
    for a in history:
        by_type[a.get("type", "?")] += 1
        by_sev[a.get("severity", "?")] += 1
        by_ip[a.get("ip", "?")] += 1
    return {
        "total":    len(history),
        "by_type":  dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "by_sev":   dict(by_sev),
        "top_ips":  sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5],
    }