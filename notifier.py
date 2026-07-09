"""
notifier.py — Telegram & Email Alert Notifications
Sends real-time notifications when CRITICAL or HIGH alerts fire.

Setup:
  Telegram: Create bot via @BotFather → get token + chat_id
  Email:    Use Gmail App Password (not regular password)

Config stored in: config/notifier.json
"""

import json, os, threading, time, socket, smtplib, urllib.request, urllib.parse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

os.makedirs("config", exist_ok=True)

CONFIG_PATH = "config/notifier.json"

DEFAULT_CONFIG = {
    "telegram": {
        "enabled":  False,
        "token":    "",          # Bot token from @BotFather
        "chat_id":  "",          # Your chat/group ID
        "min_severity": "HIGH",  # LOW / MEDIUM / HIGH / CRITICAL
    },
    "email": {
        "enabled":       False,
        "smtp_host":     "smtp.gmail.com",
        "smtp_port":     587,
        "username":      "",     # your@gmail.com
        "password":      "",     # Gmail App Password
        "from_addr":     "",     # your@gmail.com
        "to_addr":       "",     # where to send alerts
        "min_severity":  "HIGH",
    },
    "cooldown_seconds": 30,      # min gap between same alert type per IP
}

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEV_EMOJI = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}

# ── Config management ─────────────────────────────────────────────────────────
_config = None

def load_config() -> dict:
    global _config
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                loaded = json.load(f)
            # Merge with defaults
            cfg = DEFAULT_CONFIG.copy()
            cfg["telegram"].update(loaded.get("telegram", {}))
            cfg["email"].update(loaded.get("email", {}))
            cfg["cooldown_seconds"] = loaded.get("cooldown_seconds",
                                                   DEFAULT_CONFIG["cooldown_seconds"])
            _config = cfg
            return cfg
        except Exception:
            pass
    _config = DEFAULT_CONFIG.copy()
    return _config

def save_config(cfg: dict):
    global _config
    _config = cfg
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def get_config() -> dict:
    global _config
    if _config is None:
        load_config()
    return _config


# ── Cooldown tracker ──────────────────────────────────────────────────────────
_cooldown: dict = {}   # (ip, alert_type) -> last_sent timestamp

def _is_cooled(ip: str, atype: str) -> bool:
    cfg = get_config()
    key = (ip, atype)
    last = _cooldown.get(key, 0)
    if time.time() - last >= cfg.get("cooldown_seconds", 30):
        _cooldown[key] = time.time()
        return True
    return False


# ── Telegram ──────────────────────────────────────────────────────────────────
def _send_telegram(alert: dict, cfg: dict) -> bool:
    token   = cfg.get("token", "").strip()
    chat_id = cfg.get("chat_id", "").strip()
    if not token or not chat_id:
        return False

    sev   = alert.get("severity", "?")
    atype = alert.get("type", "?")
    ip    = alert.get("ip", "?")
    svc   = alert.get("service", "?")
    det   = alert.get("detail", "")
    ts    = alert.get("timestamp", datetime.now().isoformat())[:19]
    emoji = SEV_EMOJI.get(sev, "⚪")

    text = (
        f"{emoji} *Laxmi Chit Fund Honeypot Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🔸 *Type:*     `{atype}`\n"
        f"🔸 *Severity:* `{sev}`\n"
        f"🔸 *IP:*       `{ip}`\n"
        f"🔸 *Service:*  `{svc}`\n"
        f"🔸 *Time:*     `{ts}`\n"
        f"🔸 *Detail:*   {det}\n"
    )

    # Add extra fields
    for k in ("path", "filename", "tool", "payload", "attempts"):
        if k in alert:
            text += f"🔸 *{k.title()}:*  `{str(alert[k])[:60]}`\n"

    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "Markdown",
    }).encode()

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
            return result.get("ok", False)
    except Exception as e:
        print(f"[Telegram] Send failed: {e}")
        return False


def _test_telegram(token: str, chat_id: str) -> tuple[bool, str]:
    """Test Telegram credentials. Returns (success, message)."""
    if not token or not chat_id:
        return False, "Token and Chat ID required"
    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    text = "✅ Laxmi Chit Fund Honeypot connected! Alerts will be sent here."
    data = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                return True, "Test message sent successfully!"
            return False, str(result.get("description", "Unknown error"))
    except Exception as e:
        return False, str(e)


# ── Email ─────────────────────────────────────────────────────────────────────
def _send_email(alert: dict, cfg: dict) -> bool:
    host    = cfg.get("smtp_host", "smtp.gmail.com")
    port    = cfg.get("smtp_port", 587)
    user    = cfg.get("username", "").strip()
    pwd     = cfg.get("password", "").strip()
    from_   = cfg.get("from_addr", user).strip()
    to_     = cfg.get("to_addr", "").strip()

    if not all([user, pwd, to_]):
        return False

    sev   = alert.get("severity", "?")
    atype = alert.get("type", "?")
    ip    = alert.get("ip", "?")
    svc   = alert.get("service", "?")
    det   = alert.get("detail", "")
    ts    = alert.get("timestamp", datetime.now().isoformat())[:19]
    emoji = SEV_EMOJI.get(sev, "⚪")

    subject = f"{emoji} [{sev}] Honeypot Alert: {atype} from {ip}"

    # Plain text body
    plain = (
        f"Laxmi Chit Fund Honeypot — Security Alert\n"
        f"{'='*50}\n"
        f"Type     : {atype}\n"
        f"Severity : {sev}\n"
        f"IP       : {ip}\n"
        f"Service  : {svc}\n"
        f"Time     : {ts}\n"
        f"Detail   : {det}\n"
    )
    for k in ("path", "filename", "tool", "payload", "attempts"):
        if k in alert:
            plain += f"{k.title():<9}: {str(alert[k])[:80]}\n"
    plain += f"\n{'='*50}\nThis is an automated alert from Laxmi Chit Fund Honeypot Suite.\n"

    # HTML body
    color_map = {"CRITICAL": "#cc0000", "HIGH": "#ff3c5a",
                 "MEDIUM": "#ff8c00",   "LOW": "#ffab40"}
    sev_color = color_map.get(sev, "#888")
    rows = "".join(
        f"<tr><td style='padding:6px 12px;color:#888;'><b>{k.title()}</b></td>"
        f"<td style='padding:6px 12px;font-family:monospace'>{str(alert[k])[:80]}</td></tr>"
        for k in ("path", "filename", "tool", "payload", "attempts") if k in alert
    )
    html = f"""
<html><body style='font-family:Arial;background:#f5f5f5;padding:20px;'>
<div style='max-width:600px;background:#fff;border-radius:4px;
     border-left:4px solid {sev_color};padding:24px;'>
<h2 style='color:{sev_color};margin-top:0'>{emoji} {atype}</h2>
<table style='width:100%;border-collapse:collapse;'>
<tr><td style='padding:6px 12px;color:#888'><b>Severity</b></td>
    <td style='padding:6px 12px'><span style='background:{sev_color};color:#fff;
    padding:2px 8px;border-radius:10px;font-size:12px'>{sev}</span></td></tr>
<tr><td style='padding:6px 12px;color:#888'><b>IP Address</b></td>
    <td style='padding:6px 12px;font-family:monospace'>{ip}</td></tr>
<tr><td style='padding:6px 12px;color:#888'><b>Service</b></td>
    <td style='padding:6px 12px'>{svc}</td></tr>
<tr><td style='padding:6px 12px;color:#888'><b>Time</b></td>
    <td style='padding:6px 12px;font-family:monospace'>{ts}</td></tr>
<tr><td style='padding:6px 12px;color:#888'><b>Detail</b></td>
    <td style='padding:6px 12px'>{det}</td></tr>
{rows}
</table>
<p style='color:#aaa;font-size:11px;margin-top:20px;border-top:1px solid #eee;
  padding-top:12px'>Laxmi Chit Fund Honeypot Suite — Automated Security Alert</p>
</div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_
    msg["To"]      = to_
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(user, pwd)
            s.sendmail(from_, [to_], msg.as_string())
        return True
    except Exception as e:
        print(f"[Email] Send failed: {e}")
        return False


def _test_email(cfg: dict) -> tuple[bool, str]:
    """Test email credentials."""
    test_alert = {
        "type": "TEST", "severity": "LOW",
        "ip": "127.0.0.1", "service": "TEST",
        "detail": "This is a test alert from Laxmi Chit Fund Honeypot",
        "timestamp": datetime.now().isoformat(),
    }
    try:
        ok = _send_email(test_alert, cfg)
        return ok, "Test email sent!" if ok else "Failed — check credentials"
    except Exception as e:
        return False, str(e)


# ── Public API ────────────────────────────────────────────────────────────────
def notify(alert: dict):
    """
    Called by alert_system when an alert fires.
    Checks severity thresholds + cooldown, then sends notifications.
    Non-blocking — runs in background thread.
    """
    threading.Thread(target=_notify_bg, args=(alert,), daemon=True).start()


def _notify_bg(alert: dict):
    cfg   = get_config()
    sev   = alert.get("severity", "LOW")
    ip    = alert.get("ip", "")
    atype = alert.get("type", "")

    if not _is_cooled(ip, atype):
        return

    # Telegram
    tg = cfg.get("telegram", {})
    if tg.get("enabled") and \
       SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(tg.get("min_severity", "HIGH"), 2):
        _send_telegram(alert, tg)

    # Email
    em = cfg.get("email", {})
    if em.get("enabled") and \
       SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(em.get("min_severity", "HIGH"), 2):
        _send_email(alert, em)