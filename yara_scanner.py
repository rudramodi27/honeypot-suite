"""
yara_scanner.py — YARA Rules Integration
Professional malware detection using YARA signatures.

Replaces basic magic-byte detection with industry-standard
YARA rules used by CERTs, AV vendors, and DFIR teams.

Usage:
    from yara_scanner import YaraScanner
    scanner = YaraScanner()
    results = scanner.scan_file("/path/to/sample")
    results = scanner.scan_bytes(data)
    results = scanner.scan_string("eval(base64_decode(...));")
"""

import os
import logging
import json
from datetime import datetime
from typing import Optional
from pathlib import Path

logger = logging.getLogger("YaraScanner")

RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")
os.makedirs(RULES_DIR, exist_ok=True)

try:
    import yara
    YARA_OK = True
except ImportError:
    YARA_OK = False
    logger.warning("yara-python not installed — YARA scanning disabled. "
                   "Install with: pip install yara-python")


# ── Built-in YARA Rules ───────────────────────────────────────
BUILTIN_RULES = {
    "webshells.yar": r"""
rule PHP_Webshell_Generic {
    meta:
        description = "Detects generic PHP webshells"
        severity = "CRITICAL"
        author = "HoneypotSuite"
    strings:
        $eval_b64    = /eval\s*\(\s*base64_decode/
        $system_get  = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $exec_get    = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $passthru    = /passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $shell_exec  = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $assert_get  = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $preg_e      = /preg_replace\s*\(.*\/e/
        $create_func = /create_function\s*\(.*eval/
    condition:
        any of them
}

rule PHP_Webshell_B374k {
    meta:
        description = "Detects B374k PHP webshell"
        severity = "CRITICAL"
    strings:
        $s1 = "b374k"
        $s2 = "preg_replace" nocase
        $s3 = "base64_decode" nocase
    condition:
        all of them
}

rule PHP_Webshell_China_Chopper {
    meta:
        description = "Detects China Chopper webshell"
        severity = "CRITICAL"
    strings:
        $s1 = "eval($_POST[" nocase
        $s2 = "assert($_POST[" nocase
    condition:
        any of them
}

rule JSP_Webshell {
    meta:
        description = "Detects JSP webshell"
        severity = "CRITICAL"
    strings:
        $s1 = "Runtime.getRuntime().exec(" nocase
        $s2 = "ProcessBuilder" nocase
        $s3 = "getOutputStream" nocase
    condition:
        2 of them
}
""",

    "reverse_shells.yar": r"""
rule Python_Reverse_Shell {
    meta:
        description = "Detects Python reverse shell"
        severity = "CRITICAL"
    strings:
        $s1 = "import socket" nocase
        $s2 = "connect(" nocase
        $s3 = /SOCK_STREAM|subprocess\.Popen/
        $s4 = "stdin=PIPE" nocase
    condition:
        3 of them
}

rule Bash_Reverse_Shell {
    meta:
        description = "Detects Bash reverse shell"
        severity = "CRITICAL"
    strings:
        $s1 = "bash -i" nocase
        $s2 = /\/dev\/tcp\//
        $s3 = ">&" nocase
    condition:
        any of them
}

rule Netcat_Backdoor {
    meta:
        description = "Detects netcat backdoor"
        severity = "CRITICAL"
    strings:
        $s1 = "nc -e" nocase
        $s2 = "ncat -e" nocase
        $s3 = "netcat -e" nocase
    condition:
        any of them
}

rule Perl_Reverse_Shell {
    meta:
        description = "Detects Perl reverse shell"
        severity = "CRITICAL"
    strings:
        $s1 = "use Socket" nocase
        $s2 = "SOCK_STREAM" nocase
        $s3 = "exec(\"/bin/sh" nocase
    condition:
        2 of them
}
""",

    "exploits.yar": r"""
rule Log4Shell_Exploit {
    meta:
        description = "Detects Log4Shell (CVE-2021-44228) exploitation"
        severity = "CRITICAL"
        cve = "CVE-2021-44228"
    strings:
        $s1 = "${jndi:" nocase
        $s2 = "ldap://" nocase
        $s3 = "rmi://" nocase
        $s4 = "dns://" nocase
    condition:
        $s1 and any of ($s2, $s3, $s4)
}

rule ShellShock_Exploit {
    meta:
        description = "Detects ShellShock (CVE-2014-6271) exploitation"
        severity = "CRITICAL"
        cve = "CVE-2014-6271"
    strings:
        $s1 = "() { :; };" nocase
        $s2 = "() { ignored; };" nocase
    condition:
        any of them
}

rule SQL_Injection_Advanced {
    meta:
        description = "Detects advanced SQL injection payloads"
        severity = "HIGH"
    strings:
        $union   = /UNION\s+(ALL\s+)?SELECT/i
        $sleep   = /SLEEP\s*\(\s*[0-9]+\s*\)/i
        $bench   = /BENCHMARK\s*\(/i
        $hex     = /0x[0-9a-fA-F]{8,}/
        $comment = /\/\*.*\*\//
        $stacked = /;\s*(DROP|INSERT|UPDATE|DELETE|CREATE|ALTER)/i
    condition:
        any of ($union, $sleep, $bench, $stacked) or (2 of ($hex, $comment))
}

rule XSS_Payload {
    meta:
        description = "Detects XSS payloads"
        severity = "MEDIUM"
    strings:
        $s1 = "<script>" nocase
        $s2 = "javascript:" nocase
        $s3 = "onerror=" nocase
        $s4 = "onload=" nocase
        $s5 = "alert(" nocase
    condition:
        2 of them
}

rule LFI_Exploit {
    meta:
        description = "Detects Local File Inclusion attempts"
        severity = "HIGH"
    strings:
        $s1 = "../../../etc/passwd" nocase
        $s2 = "..\\..\\..\\windows\\system32" nocase
        $s3 = "/proc/self/environ" nocase
        $s4 = "php://filter" nocase
        $s5 = "php://input" nocase
    condition:
        any of them
}
""",

    "cryptominer.yar": r"""
rule Cryptominer_Stratum {
    meta:
        description = "Detects cryptominer stratum protocol"
        severity = "HIGH"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "mining.subscribe" nocase
        $s3 = "mining.authorize" nocase
        $s4 = "xmrig" nocase
        $s5 = "monero" nocase
    condition:
        2 of them
}

rule XMRig_Miner {
    meta:
        description = "Detects XMRig CPU miner"
        severity = "HIGH"
    strings:
        $s1 = "--donate-level" nocase
        $s2 = "--pool-user" nocase
        $s3 = "pool.minexmr.com" nocase
        $s4 = "supportxmr.com" nocase
    condition:
        any of them
}
""",

    "persistence.yar": r"""
rule Crontab_Persistence {
    meta:
        description = "Detects crontab persistence mechanism"
        severity = "HIGH"
    strings:
        $s1 = "crontab -e" nocase
        $s2 = "/etc/cron." nocase
        $s3 = "cron.d" nocase
    condition:
        any of them
}

rule SSH_Key_Persistence {
    meta:
        description = "Detects SSH key persistence"
        severity = "HIGH"
    strings:
        $s1 = "authorized_keys" nocase
        $s2 = "ssh-rsa" nocase
        $s3 = "ssh-ed25519" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule Systemd_Service_Persistence {
    meta:
        description = "Detects systemd service persistence"
        severity = "MEDIUM"
    strings:
        $s1 = "[Unit]" nocase
        $s2 = "[Service]" nocase
        $s3 = "ExecStart=" nocase
        $s4 = "[Install]" nocase
    condition:
        3 of them
}
""",
}


class YaraScanner:
    """
    Production-grade YARA scanner with:
    - Compiled rule caching
    - Hot-reload on rule change
    - CVE/severity metadata extraction
    - String match context
    """

    def __init__(self, rules_dir: str = RULES_DIR):
        self.rules_dir = rules_dir
        os.makedirs(self.rules_dir, exist_ok=True)
        self._compiled = None
        self._rules_mtime: dict = {}
        self._write_builtin_rules()
        self._compile()

    def _write_builtin_rules(self):
        """Write built-in rules to disk if not already present."""
        for fname, content in BUILTIN_RULES.items():
            path = os.path.join(self.rules_dir, fname)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(content)
                logger.info(f"Wrote built-in YARA rule: {fname}")

    def _needs_recompile(self) -> bool:
        """Check if any rule file has changed."""
        if self._compiled is None:
            return True
        for rule_file in Path(self.rules_dir).glob("*.yar"):
            mtime = rule_file.stat().st_mtime
            if self._rules_mtime.get(str(rule_file)) != mtime:
                return True
        return False

    def _compile(self):
        """Compile all .yar files in rules directory."""
        if not YARA_OK:
            return
        rule_files = list(Path(self.rules_dir).glob("*.yar"))
        if not rule_files:
            logger.warning("No YARA rule files found")
            return
        filepaths = {f.stem: str(f) for f in rule_files}
        try:
            self._compiled = yara.compile(filepaths=filepaths)
            self._rules_mtime = {str(f): f.stat().st_mtime for f in rule_files}
            logger.info(f"YARA: compiled {len(rule_files)} rule files")
        except yara.SyntaxError as e:
            logger.error(f"YARA compile error: {e}")
            self._compiled = None

    def _ensure_fresh(self):
        if self._needs_recompile():
            self._compile()

    def _format_matches(self, matches) -> list[dict]:
        results = []
        for match in matches:
            meta = match.meta or {}
            results.append({
                "rule":        match.rule,
                "namespace":   match.namespace,
                "severity":    meta.get("severity", "MEDIUM"),
                "description": meta.get("description", ""),
                "cve":         meta.get("cve", ""),
                "strings":     [
                    {
                        "offset":    s.instances[0].offset if s.instances else 0,
                        "name":      s.identifier,
                        "data":      repr(s.instances[0].matched_data[:64]) if s.instances else "",
                    }
                    for s in match.strings[:5]           # first 5 string hits
                ],
                "tags":        list(match.tags),
            })
        return results

    def scan_file(self, filepath: str, timeout: int = 30) -> dict:
        """Scan a file on disk."""
        if not YARA_OK or not self._compiled:
            return {"yara_available": False, "matches": []}
        self._ensure_fresh()
        try:
            matches = self._compiled.match(filepath, timeout=timeout)
            results = self._format_matches(matches)
            return {
                "yara_available": True,
                "file":          filepath,
                "match_count":   len(results),
                "matches":       results,
                "max_severity":  self._max_severity(results),
            }
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout: {filepath}")
            return {"yara_available": True, "matches": [], "error": "timeout"}
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return {"yara_available": True, "matches": [], "error": str(e)}

    def scan_bytes(self, data: bytes, timeout: int = 10) -> dict:
        """Scan raw bytes."""
        if not YARA_OK or not self._compiled:
            return {"yara_available": False, "matches": []}
        self._ensure_fresh()
        try:
            matches = self._compiled.match(data=data, timeout=timeout)
            results = self._format_matches(matches)
            return {
                "yara_available": True,
                "match_count":   len(results),
                "matches":       results,
                "max_severity":  self._max_severity(results),
            }
        except Exception as e:
            return {"yara_available": True, "matches": [], "error": str(e)}

    def scan_string(self, text: str, timeout: int = 10) -> dict:
        """Scan a string (commands, payloads, etc.)."""
        return self.scan_bytes(text.encode("utf-8", errors="replace"), timeout)

    @staticmethod
    def _max_severity(results: list[dict]) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not results:
            return "NONE"
        return max((r.get("severity", "LOW") for r in results),
                   key=lambda s: order.get(s, 0))

    def reload_rules(self):
        """Force hot-reload of rules from disk."""
        self._rules_mtime = {}
        self._compile()
        logger.info("YARA rules reloaded")

    def add_rule(self, name: str, content: str) -> bool:
        """Dynamically add a new YARA rule file."""
        path = os.path.join(self.rules_dir, f"{name}.yar")
        try:
            # Validate syntax first
            yara.compile(source=content)
            with open(path, "w") as f:
                f.write(content)
            self.reload_rules()
            logger.info(f"Added YARA rule: {name}")
            return True
        except yara.SyntaxError as e:
            logger.error(f"Invalid YARA syntax in {name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to add YARA rule {name}: {e}")
            return False


# ── Module-level singleton ────────────────────────────────────
_scanner: Optional[YaraScanner] = None

def get_scanner() -> YaraScanner:
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner()
    return _scanner


if __name__ == "__main__":
    # Quick test
    sc = YaraScanner()
    test_payload = b"<?php eval(base64_decode($_POST['cmd'])); ?>"
    result = sc.scan_bytes(test_payload)
    print(json.dumps(result, indent=2))
