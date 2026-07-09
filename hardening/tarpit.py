"""
hardening/tarpit.py — SSH Brute-Force Tarpit

ssh_honeypot.py's check_auth_password() already adds a small randomized
delay (1.0-2.5s) on every failure — useful against naive single-shot
scanners, but not enough to meaningfully waste a determined brute-force
tool's time. A tarpit specifically targets REPEAT offenders: after N
failed attempts from the same IP within a tracking window, every
subsequent attempt from that IP gets held open for `tarpit_delay`
seconds before responding.

Config (config.yaml `deception` section):
    deception:
      tarpit_enabled: true
      tarpit_delay: 30
      max_attempts_before_tarpit: 5

Wired into ssh_honeypot.SSHServer.check_auth_password via a monkey-patch
in run.py's _patch_existing_modules(), consistent with how
logger.log()/alert_system.trigger()/mitre_attack.map_and_log() are
already patched there — additive, doesn't modify ssh_honeypot.py
directly.

TESTED in this session: see the self-test at the bottom, which
exercises the full failure-count → tarpit-delay → window-expiry cycle
without needing a real SSH client.
"""

import time
import threading
import logging
from collections import defaultdict

logger = logging.getLogger("Tarpit")

try:
    from config_loader import cfg
    TARPIT_ENABLED   = cfg.get("deception.tarpit_enabled", True)
    TARPIT_DELAY     = cfg.get("deception.tarpit_delay", 30)
    MAX_ATTEMPTS     = cfg.get("deception.max_attempts_before_tarpit", 5)
except Exception:
    TARPIT_ENABLED, TARPIT_DELAY, MAX_ATTEMPTS = True, 30, 5

TRACKING_WINDOW_SECONDS = 300   # failures older than this don't count toward the threshold

_lock = threading.Lock()
_failure_log: dict = defaultdict(list)   # ip -> [timestamp, timestamp, ...]


def _prune_old(ip: str, now: float):
    cutoff = now - TRACKING_WINDOW_SECONDS
    _failure_log[ip] = [t for t in _failure_log[ip] if t > cutoff]


def record_failure(ip: str) -> int:
    """Record a failed auth attempt for `ip`. Returns the current
    in-window failure count (after recording this one)."""
    now = time.time()
    with _lock:
        _prune_old(ip, now)
        _failure_log[ip].append(now)
        return len(_failure_log[ip])


def should_tarpit(ip: str) -> bool:
    """Has this IP crossed the threshold within the tracking window?"""
    if not TARPIT_ENABLED:
        return False
    with _lock:
        _prune_old(ip, time.time())
        return len(_failure_log[ip]) >= MAX_ATTEMPTS


def get_delay(ip: str) -> float:
    """Delay (seconds) to apply for this IP's current attempt, given
    its failure history. Call record_failure() first, then
    get_delay(), so the delay reflects the count including the
    attempt that just failed."""
    if not TARPIT_ENABLED:
        return 0.0
    with _lock:
        _prune_old(ip, time.time())
        count = len(_failure_log[ip])
    return float(TARPIT_DELAY) if count >= MAX_ATTEMPTS else 0.0


def reset(ip: str):
    """Clear an IP's failure history — call on successful auth, so a
    legitimate login isn't penalized for prior unrelated failed
    attempts from the same address."""
    with _lock:
        _failure_log.pop(ip, None)


def stats() -> dict:
    """Snapshot for the dashboard / debugging — counts only."""
    with _lock:
        now = time.time()
        return {
            ip: len([t for t in timestamps if t > now - TRACKING_WINDOW_SECONDS])
            for ip, timestamps in _failure_log.items()
        }


def apply_tarpit_delay(ip: str):
    """Blocking call — holds the current thread (and therefore the
    attacker's open TCP connection) for tarpit_delay seconds. Each
    honeypot connection already runs in its own thread (see
    ssh_honeypot.py's per-connection handler), so this only blocks the
    one attacker's session, not the whole listener."""
    delay = get_delay(ip)
    if delay > 0:
        logger.info(f"Tarpit engaged for {ip} — holding connection {delay}s "
                    f"({len(_failure_log.get(ip, []))} failures in window)")
        time.sleep(delay)


def patch_ssh_honeypot():
    """Monkey-patch ssh_honeypot.SSHServer.check_auth_password to
    record failures and apply the tarpit delay on top of the existing
    randomized brute-force delay. Called from run.py alongside the
    other three patches in _patch_existing_modules()."""
    try:
        import ssh_honeypot
        from paramiko.common import AUTH_FAILED
    except ImportError as e:
        logger.warning(f"Cannot patch SSH tarpit — ssh_honeypot/paramiko unavailable: {e}")
        return

    original = ssh_honeypot.SSHServer.check_auth_password

    def patched(self, username, password):
        result = original(self, username, password)
        if result == AUTH_FAILED:
            record_failure(self.ip)
            if should_tarpit(self.ip):
                apply_tarpit_delay(self.ip)
        else:
            reset(self.ip)
        return result

    ssh_honeypot.SSHServer.check_auth_password = patched
    logger.info(f"[OK] SSH tarpit patched in - threshold={MAX_ATTEMPTS} attempts, "
                f"delay={TARPIT_DELAY}s, window={TRACKING_WINDOW_SECONDS}s")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    attacker_ip = "203.0.113.50"
    clean_ip = "203.0.113.99"

    print(f"Config: enabled={TARPIT_ENABLED}, threshold={MAX_ATTEMPTS}, delay={TARPIT_DELAY}s")
    print()

    for i in range(1, MAX_ATTEMPTS + 3):
        count = record_failure(attacker_ip)
        tarpitted = should_tarpit(attacker_ip)
        delay = get_delay(attacker_ip)
        print(f"  Attempt {i}: failure_count={count}, "
              f"tarpit_active={tarpitted}, would_delay={delay}s")

    print()
    print(f"Clean IP {clean_ip} (no failures recorded): "
          f"tarpit_active={should_tarpit(clean_ip)}")

    print()
    print("Resetting attacker IP (simulating eventual successful auth)...")
    reset(attacker_ip)
    print(f"After reset: tarpit_active={should_tarpit(attacker_ip)}")

    assert should_tarpit(attacker_ip) is False, "reset() should clear tarpit state"
    print()
    print("Self-test PASSED.")
