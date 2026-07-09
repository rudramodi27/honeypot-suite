"""
mitre_attack.py — MITRE ATT&CK Framework Mapping
Maps honeypot events and attacker behaviors to MITRE ATT&CK techniques.

Reference: https://attack.mitre.org/
Tactics covered: Reconnaissance, Initial Access, Execution,
                 Persistence, Privilege Escalation, Discovery,
                 Lateral Movement, Collection, Exfiltration

Each event gets:
  - Tactic (e.g. Initial Access)
  - Technique ID (e.g. T1110)
  - Technique Name (e.g. Brute Force)
  - Sub-technique (e.g. T1110.001 Password Guessing)
  - Confidence (HIGH / MEDIUM / LOW)
  - Description
"""

import json, os
from datetime import datetime
from collections import defaultdict

os.makedirs("logs", exist_ok=True)
MITRE_LOG = "logs/mitre_mappings.log"


# ── MITRE ATT&CK Technique Database ──────────────────────────────────────────
# Format: rule_key -> technique info
TECHNIQUES = {
    # ── Reconnaissance ────────────────────────────────────────────────────────
    "T1595.001": {
        "tactic":      "Reconnaissance",
        "tactic_id":   "TA0043",
        "technique":   "Active Scanning: Scanning IP Blocks",
        "id":          "T1595.001",
        "url":         "https://attack.mitre.org/techniques/T1595/001/",
        "description": "Attacker scanned IP ranges to find open services.",
    },
    "T1595.002": {
        "tactic":      "Reconnaissance",
        "tactic_id":   "TA0043",
        "technique":   "Active Scanning: Vulnerability Scanning",
        "id":          "T1595.002",
        "url":         "https://attack.mitre.org/techniques/T1595/002/",
        "description": "Attacker used automated vulnerability scanner.",
    },
    "T1592.002": {
        "tactic":      "Reconnaissance",
        "tactic_id":   "TA0043",
        "technique":   "Gather Victim Host Info: Software",
        "id":          "T1592.002",
        "url":         "https://attack.mitre.org/techniques/T1592/002/",
        "description": "Attacker probed server banners to identify software.",
    },

    # ── Initial Access ────────────────────────────────────────────────────────
    "T1110.001": {
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "technique":   "Brute Force: Password Guessing",
        "id":          "T1110.001",
        "url":         "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Attacker attempted common/default passwords.",
    },
    "T1110.003": {
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "technique":   "Brute Force: Password Spraying",
        "id":          "T1110.003",
        "url":         "https://attack.mitre.org/techniques/T1110/003/",
        "description": "Attacker tried same password across multiple usernames.",
    },
    "T1190": {
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "technique":   "Exploit Public-Facing Application",
        "id":          "T1190",
        "url":         "https://attack.mitre.org/techniques/T1190/",
        "description": "Attacker attempted to exploit web application vulnerabilities.",
    },
    "T1078.001": {
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "technique":   "Valid Accounts: Default Accounts",
        "id":          "T1078.001",
        "url":         "https://attack.mitre.org/techniques/T1078/001/",
        "description": "Attacker used default credentials (admin/admin).",
    },

    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.004": {
        "tactic":      "Execution",
        "tactic_id":   "TA0002",
        "technique":   "Command and Scripting Interpreter: Unix Shell",
        "id":          "T1059.004",
        "url":         "https://attack.mitre.org/techniques/T1059/004/",
        "description": "Attacker executed commands via Unix shell.",
    },
    "T1059.006": {
        "tactic":      "Execution",
        "tactic_id":   "TA0002",
        "technique":   "Command and Scripting Interpreter: Python",
        "id":          "T1059.006",
        "url":         "https://attack.mitre.org/techniques/T1059/006/",
        "description": "Attacker attempted to execute Python scripts.",
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1505.003": {
        "tactic":      "Persistence",
        "tactic_id":   "TA0003",
        "technique":   "Server Software Component: Web Shell",
        "id":          "T1505.003",
        "url":         "https://attack.mitre.org/techniques/T1505/003/",
        "description": "Attacker uploaded a web shell for persistent access.",
    },
    "T1053.003": {
        "tactic":      "Persistence",
        "tactic_id":   "TA0003",
        "technique":   "Scheduled Task/Job: Cron",
        "id":          "T1053.003",
        "url":         "https://attack.mitre.org/techniques/T1053/003/",
        "description": "Attacker checked crontab for persistence opportunities.",
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1083": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "File and Directory Discovery",
        "id":          "T1083",
        "url":         "https://attack.mitre.org/techniques/T1083/",
        "description": "Attacker enumerated files and directories.",
    },
    "T1057": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "Process Discovery",
        "id":          "T1057",
        "url":         "https://attack.mitre.org/techniques/T1057/",
        "description": "Attacker listed running processes (ps aux).",
    },
    "T1049": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "System Network Connections Discovery",
        "id":          "T1049",
        "url":         "https://attack.mitre.org/techniques/T1049/",
        "description": "Attacker checked network connections (netstat/ss).",
    },
    "T1082": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "System Information Discovery",
        "id":          "T1082",
        "url":         "https://attack.mitre.org/techniques/T1082/",
        "description": "Attacker gathered OS and system information.",
    },
    "T1033": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "System Owner/User Discovery",
        "id":          "T1033",
        "url":         "https://attack.mitre.org/techniques/T1033/",
        "description": "Attacker checked current user (whoami/id).",
    },
    "T1087.001": {
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "technique":   "Account Discovery: Local Account",
        "id":          "T1087.001",
        "url":         "https://attack.mitre.org/techniques/T1087/001/",
        "description": "Attacker read /etc/passwd to enumerate accounts.",
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1548.003": {
        "tactic":      "Privilege Escalation",
        "tactic_id":   "TA0004",
        "technique":   "Abuse Elevation Control: Sudo and Sudo Caching",
        "id":          "T1548.003",
        "url":         "https://attack.mitre.org/techniques/T1548/003/",
        "description": "Attacker attempted sudo for privilege escalation.",
    },

    # ── Collection ────────────────────────────────────────────────────────────
    "T1005": {
        "tactic":      "Collection",
        "tactic_id":   "TA0009",
        "technique":   "Data from Local System",
        "id":          "T1005",
        "url":         "https://attack.mitre.org/techniques/T1005/",
        "description": "Attacker accessed sensitive local files.",
    },
    "T1213": {
        "tactic":      "Collection",
        "tactic_id":   "TA0009",
        "technique":   "Data from Information Repositories",
        "id":          "T1213",
        "url":         "https://attack.mitre.org/techniques/T1213/",
        "description": "Attacker accessed database or config files.",
    },

    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041": {
        "tactic":      "Exfiltration",
        "tactic_id":   "TA0010",
        "technique":   "Exfiltration Over C2 Channel",
        "id":          "T1041",
        "url":         "https://attack.mitre.org/techniques/T1041/",
        "description": "Attacker attempted to download sensitive data.",
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1552.001": {
        "tactic":      "Credential Access",
        "tactic_id":   "TA0006",
        "technique":   "Unsecured Credentials: Credentials in Files",
        "id":          "T1552.001",
        "url":         "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Attacker searched for credentials in config files.",
    },

    # ── Injection ─────────────────────────────────────────────────────────────
    "T1190.sql": {
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "technique":   "Exploit Public-Facing Application: SQL Injection",
        "id":          "T1190",
        "url":         "https://attack.mitre.org/techniques/T1190/",
        "description": "Attacker attempted SQL injection attack.",
    },
}


# ── Event → Technique Mapping Rules ──────────────────────────────────────────
def _map_event(event: dict) -> list[dict]:
    """Map a single log event to one or more MITRE techniques."""
    evt     = event.get("event", "")
    cmd     = (event.get("command", "") or "").lower().strip()
    payload = (event.get("payload", "") or "").lower()
    svc     = event.get("service", "")
    ua      = (event.get("user_agent", "") or "").lower()
    path    = (event.get("path", "") or "").lower()
    tool    = (event.get("tool", "") or "").lower()

    results = []

    def _add(tid: str, confidence: str = "MEDIUM"):
        if tid in TECHNIQUES:
            t = dict(TECHNIQUES[tid])
            t["confidence"]  = confidence
            t["event"]       = evt
            t["ip"]          = event.get("ip", "")
            t["service"]     = svc
            t["timestamp"]   = event.get("timestamp", "")
            t["mapped_from"] = evt
            results.append(t)

    # ── Scanner / recon ───────────────────────────────────────────────────────
    # NOTE: logger.detect_scanner() recognizes 26 tool signatures (sqlmap,
    # hydra, nessus, metasploit, nuclei, acunetix, etc. — see logger.py
    # SCANNER_UA) but only 5 used to trigger this mapping. Any non-empty
    # `tool` value already passed that upstream allowlist, so treat it as
    # sufficient on its own instead of re-restricting to a 5-item subset.
    if evt == "SCANNER_DETECTED" or tool:
        _add("T1595.001", "HIGH")
        _add("T1595.002", "HIGH")

    if tool in ("nikto", "dirsearch", "gobuster", "wfuzz", "sqlmap", "nuclei",
                "acunetix", "nessus", "openvas", "zgrab"):
        _add("T1592.002", "HIGH")

    # ── Brute force ───────────────────────────────────────────────────────────
    if evt in ("BRUTE_FORCE", "LOGIN_FAILURE", "AUTH_FAILURE"):
        _add("T1110.001", "HIGH")

    if evt == "BRUTE_FORCE":
        _add("T1110.003", "MEDIUM")

    # ── Default credentials ───────────────────────────────────────────────────
    if evt == "LOGIN_SUCCESS":
        pwd = event.get("password", "")
        usr = event.get("username", "")
        if pwd in ("admin", "password", "123456", "root", "") and \
           usr in ("admin", "root", "administrator", "guest", "anonymous"):
            _add("T1078.001", "HIGH")

    # ── SQL injection ─────────────────────────────────────────────────────────
    if evt == "SQLI_ATTEMPT":
        _add("T1190.sql", "HIGH")
        _add("T1190", "HIGH")

    # ── Web shell upload ──────────────────────────────────────────────────────
    if evt in ("WEBSHELL_UPLOAD", "MALICIOUS_UPLOAD"):
        _add("T1505.003", "HIGH")
        _add("T1190", "HIGH")

    # ── SSH commands ──────────────────────────────────────────────────────────
    if svc == "SSH" and cmd:
        _add("T1059.004", "HIGH")

        # File discovery
        if cmd.startswith("ls") or cmd.startswith("find") or cmd.startswith("locate"):
            _add("T1083", "HIGH")

        # Process discovery
        if cmd.startswith("ps") or "ps " in cmd:
            _add("T1057", "HIGH")

        # Network discovery
        if cmd in ("netstat -tulpn", "ss -tulpn", "netstat", "ss") or \
           "netstat" in cmd or " ss " in cmd:
            _add("T1049", "HIGH")

        # System info
        if "uname" in cmd or "hostname" in cmd or "lsb_release" in cmd:
            _add("T1082", "HIGH")

        # User info
        if "whoami" in cmd or cmd.startswith("id"):
            _add("T1033", "HIGH")

        # Account discovery
        if "/etc/passwd" in cmd:
            _add("T1087.001", "HIGH")

        # Crontab check
        if "crontab" in cmd or "cron" in cmd:
            _add("T1053.003", "MEDIUM")

        # Sudo attempt
        if cmd.startswith("sudo") or cmd.startswith("su "):
            _add("T1548.003", "HIGH")

        # Credential files
        if any(f in cmd for f in ["config.php", ".env", "database.yml",
                                   "config.ini", "password", "passwd",
                                   "credentials", "backup_creds"]):
            _add("T1552.001", "HIGH")
            _add("T1005", "HIGH")

        # Python execution attempt
        if "python" in cmd or "python3" in cmd or "perl" in cmd:
            _add("T1059.006", "MEDIUM")

    # ── Bait file access ──────────────────────────────────────────────────────
    if evt in ("BAIT_FILE_ACCESS", "SSH_BAIT_FILE", "FTP_DOWNLOAD_BAIT"):
        _add("T1005", "HIGH")
        _add("T1213", "HIGH")
        _add("T1041", "MEDIUM")

    # ── FTP download attempt ──────────────────────────────────────────────────
    if evt == "RETR_ATTEMPT" or (svc == "FTP" and "RETR" in evt):
        _add("T1041", "MEDIUM")
        _add("T1005", "MEDIUM")

    # ── Config/credential file access ─────────────────────────────────────────
    if path and any(f in path for f in [".env", "config", "database",
                                         "backup", "credentials"]):
        _add("T1552.001", "HIGH")

    return results


# ── Session-level attack chain detection ─────────────────────────────────────
def analyze_session(events: list[dict]) -> dict:
    """
    Analyze all events from one session.
    Returns: tactics used, kill chain stage, severity score, IOCs
    """
    all_techniques = []
    tactics_seen   = set()
    iocs           = {"ips": set(), "usernames": set(), "passwords": set(),
                      "files": set(), "payloads": set(), "tools": set()}

    for e in events:
        techs = _map_event(e)
        all_techniques.extend(techs)
        for t in techs:
            tactics_seen.add(t["tactic"])

        # Collect IOCs
        if ip := e.get("ip"):        iocs["ips"].add(ip)
        if u  := e.get("username"):  iocs["usernames"].add(u)
        if p  := e.get("password"):  iocs["passwords"].add(p)
        if f  := e.get("filename"):  iocs["files"].add(f)
        if pl := e.get("payload"):   iocs["payloads"].add(pl[:100])
        if tl := e.get("tool"):      iocs["tools"].add(tl)

    # Kill chain stage
    KILL_CHAIN_ORDER = [
        "Reconnaissance", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Discovery",
        "Lateral Movement", "Collection", "Exfiltration",
    ]
    highest_stage = "Reconnaissance"
    for stage in reversed(KILL_CHAIN_ORDER):
        if stage in tactics_seen:
            highest_stage = stage
            break

    # Severity score (0-100)
    score = 0
    HIGH_TACTICS = {"Persistence", "Privilege Escalation",
                    "Collection", "Exfiltration"}
    MED_TACTICS  = {"Initial Access", "Execution", "Discovery"}
    for t in tactics_seen:
        if t in HIGH_TACTICS: score += 25
        elif t in MED_TACTICS: score += 15
        else: score += 5
    score = min(score, 100)

    return {
        "techniques":    all_techniques,
        "tactics":       sorted(tactics_seen),
        "kill_chain_stage": highest_stage,
        "severity_score":   score,
        "technique_count":  len(set(t["id"] for t in all_techniques)),
        "iocs": {k: list(v) for k, v in iocs.items()},
    }


# ── Map single event and log it ───────────────────────────────────────────────
def map_and_log(event: dict) -> list[dict]:
    """Map event to techniques and append to mitre log."""
    techniques = _map_event(event)
    if techniques:
        try:
            with open(MITRE_LOG, "a") as f:
                for t in techniques:
                    f.write(json.dumps(t) + "\n")
        except Exception:
            pass
    return techniques


# ── Load all mappings ─────────────────────────────────────────────────────────
def load_mappings(limit: int = 500) -> list[dict]:
    entries = []
    try:
        with open(MITRE_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: entries.append(json.loads(line))
                    except Exception: pass
    except FileNotFoundError:
        pass
    return entries[-limit:]


def get_stats() -> dict:
    mappings = load_mappings(1000)
    by_tactic    = defaultdict(int)
    by_technique = defaultdict(int)
    by_confidence= defaultdict(int)

    for m in mappings:
        by_tactic[m.get("tactic", "?")]         += 1
        by_technique[m.get("technique", "?")]   += 1
        by_confidence[m.get("confidence", "?")]  += 1

    return {
        "total":        len(mappings),
        "by_tactic":    sorted(by_tactic.items(),     key=lambda x: x[1], reverse=True),
        "by_technique": sorted(by_technique.items(),  key=lambda x: x[1], reverse=True)[:15],
        "by_confidence":dict(by_confidence),
    }


if __name__ == "__main__":
    # CLI demo
    test_events = [
        {"event": "BRUTE_FORCE",    "ip": "1.2.3.4", "service": "SSH",
         "username": "root", "password": "admin"},
        {"event": "LOGIN_SUCCESS",  "ip": "1.2.3.4", "service": "SSH",
         "username": "admin", "password": "admin"},
        {"event": "SSH_COMMAND",    "ip": "1.2.3.4", "service": "SSH",
         "command": "cat /etc/passwd"},
        {"event": "SSH_COMMAND",    "ip": "1.2.3.4", "service": "SSH",
         "command": "ps aux"},
        {"event": "WEBSHELL_UPLOAD","ip": "1.2.3.4", "service": "HTTP",
         "filename": "shell.php"},
    ]
    result = analyze_session(test_events)
    print(f"\nKill Chain Stage : {result['kill_chain_stage']}")
    print(f"Severity Score   : {result['severity_score']}/100")
    print(f"Tactics Used     : {result['tactics']}")
    print(f"Techniques Found : {result['technique_count']}")
    print(f"\nDetailed techniques:")
    seen = set()
    for t in result["techniques"]:
        if t["id"] not in seen:
            seen.add(t["id"])
            print(f"  [{t['id']}] {t['technique']} ({t['confidence']})")