"""
http_honeypot.py — Laxmi Chit Fund Internal Systems Honeypot (HTTP)
Features: 2-step login, CAPTCHA, multiple internal-admin pages, fake data tables,
          SQL injection traps, file upload trap, hidden bait directories,
          scanner detection, robots.txt bait, session expiry, delay injection

Brand: "Laxmi Chit Fund" — a wholly fictional financial institution created
solely as a honeypot decoy. Not modeled on any real bank. Internal-infra
theme only: no customer login, OTP, KYC, payments, or transaction pages
are implemented anywhere in this suite.
"""

import threading, logging, json, os, re, time, secrets, random, hashlib, io
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import logger as hp_log
import alert_system as alerts
try:
    import malware_capture as mc
    _MC_OK = True
except ImportError: _MC_OK = False

# ── Sessions: token -> {username, ip, created, last_active} ──────────────────
_http_sessions: dict = {}
SESSION_TIMEOUT = 1800  # 30 minutes

def _new_http_session(username: str, ip: str) -> str:
    token = secrets.token_hex(20)
    _http_sessions[token] = {
        "username": username, "ip": ip,
        "created": time.time(), "last_active": time.time(),
        "fail_count": 0,
    }
    return token

def _validate_session(token: str) -> dict | None:
    sess = _http_sessions.get(token)
    if not sess:
        return None
    if time.time() - sess["last_active"] > SESSION_TIMEOUT:
        _http_sessions.pop(token, None)
        return None
    sess["last_active"] = time.time()
    return sess

def _get_session_from_cookie(cookie_hdr: str) -> tuple[str, dict | None]:
    for part in (cookie_hdr or "").split(";"):
        part = part.strip()
        if part.startswith("ASP.NET_SessionId="):
            token = part.split("=", 1)[1]
            return token, _validate_session(token)
    return "", None

# ── CAPTCHA store: ip -> (code, expires) ─────────────────────────────────────
_captchas: dict = {}
import string as _string

def _new_captcha(ip: str) -> str:
    code = ''.join(random.choices(_string.ascii_letters + _string.digits, k=6))
    _captchas[ip] = (code, time.time() + 300)
    return code

def _get_captcha(ip: str) -> str:
    code, exp = _captchas.get(ip, ("", 0))
    if time.time() > exp:
        return _new_captcha(ip)
    return code

# ── Fake data (internal-infra flavored; no real customer data of any kind) ───
FAKE_BRANCHES = [
    ("BR-001", "HQ — Ahmedabad Tower",     "Gujarat",     "Online",  "Active"),
    ("BR-014", "Vastrapur Branch",          "Gujarat",     "Online",  "Active"),
    ("BR-022", "Navrangpura Branch",        "Gujarat",     "Online",  "Active"),
    ("BR-031", "Surat Ring Road Branch",    "Gujarat",     "Online",  "Active"),
    ("BR-045", "Rajkot Branch",             "Gujarat",     "Degraded","Maint. Window"),
    ("BR-050", "Vadodara Branch",           "Gujarat",     "Online",  "Active"),
    ("BR-061", "Mumbai Andheri Branch",     "Maharashtra", "Online",  "Active"),
    ("BR-070", "Pune Kothrud Branch",       "Maharashtra", "Offline", "Under Review"),
    ("BR-090", "Delhi CP Branch",           "Delhi",       "Online",  "Active"),
    ("BR-101", "Bengaluru Koramangala",     "Karnataka",   "Online",  "Active"),
]

FAKE_EMPLOYEES = [
    ("LCF-2005", "R.K. Sharma",   "Branch Operations", "Branch Manager",     "Active"),
    ("LCF-3011", "Amit Kumar",    "IT Infrastructure",  "Systems Admin",      "Active"),
    ("LCF-3012", "Sneha Joshi",   "IT Infrastructure",  "DevOps Engineer",    "Active"),
    ("LCF-4020", "P.N. Mehta",    "Risk & Compliance",  "Compliance Officer", "Active"),
    ("LCF-5033", "K.R. Trivedi",  "Security",           "SOC Analyst",        "On Leave"),
]

FAKE_SERVERS = [
    ("lcf-core01",  "Core Ledger Node",        "10.20.1.10", "Online",  "62%"),
    ("lcf-core02",  "Core Ledger Node (Replica)","10.20.1.11","Online", "58%"),
    ("lcf-auth01",  "Auth / Directory Service", "10.20.2.5",  "Online",  "41%"),
    ("lcf-db01",    "Primary Database",         "10.20.3.10", "Online",  "77%"),
    ("lcf-db02",    "Warm Standby Database",    "10.20.3.11", "Online",  "12%"),
    ("lcf-mail01",  "Mail Relay",               "10.20.4.2",  "Degraded","—"),
    ("lcf-vpn01",   "Branch VPN Concentrator",  "10.20.5.1",  "Online",  "34%"),
]

FAKE_LOGS = [
    ("2026-07-02 09:12:33", "192.168.1.100", "GET /admin/dashboard",        "200", "Mozilla/5.0"),
    ("2026-07-02 09:15:01", "10.0.0.5",      "POST /admin/branches",        "200", "Mozilla/5.0"),
    ("2026-07-02 10:22:15", "203.0.113.42",  "GET /admin/export",           "403", "python-requests/2.28"),
    ("2026-07-02 11:05:44", "198.51.100.7",  "GET /backup/core_dump.sql",   "200", "Go-http-client/1.1"),
    ("2026-07-02 11:06:01", "198.51.100.7",  "GET /config/db.php",          "404", "Go-http-client/1.1"),
]

FAKE_INCIDENTS = [
    ("INC-4471", "Repeated auth failures — VPN gateway",     "High",   "Investigating"),
    ("INC-4468", "Unusual export volume — Branch BR-070",    "Medium", "Monitoring"),
    ("INC-4460", "TLS cert expiring — mail relay",           "Low",    "Scheduled"),
]

FAKE_BACKUPS = [
    ("core-ledger-full",  "2026-07-06 03:00", "SUCCESS", "42.1 GB"),
    ("branch-config",     "2026-07-06 03:10", "SUCCESS", "118 MB"),
    ("employee-directory","2026-07-06 03:12", "SUCCESS", "6.4 MB"),
    ("mail-archive",      "2026-07-05 03:00", "FAILED",  "—"),
]

FAKE_DOCS = [
    ("SOP-114", "Branch Opening Checklist",         "Operations", "v3.2"),
    ("SOP-207", "Incident Escalation Matrix",        "Security",   "v1.9"),
    ("POL-002", "Data Retention Policy (Internal)",  "Compliance", "v4.0"),
    ("RUN-018", "Core Ledger Failover Runbook",      "IT Infra",   "v2.1"),
]

# ── Brand palette (blue + gold, dark/light) ──────────────────────────────────
_THEME_CSS = """
:root{
  --navy:#0d2340; --navy-2:#123a66; --navy-3:#0b1c33;
  --gold:#c9a227; --gold-light:#e6c667; --gold-dim:#8a6d15;
  --bg:#f4f6fb; --card:#ffffff; --border:#dbe2ef; --text:#1c2537; --muted:#64708a;
  --ok:#1f9d63; --warn:#c8811a; --err:#d1483f; --info:#123a66;
}
[data-theme="dark"]{
  --bg:#0b1220; --card:#111b30; --border:#233252; --text:#e7ecf7; --muted:#93a1c2;
  --navy:#12294b; --navy-2:#1a3f70;
}
*{box-sizing:border-box;}
body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text);transition:background .25s,color .25s;}
a{color:var(--navy-2);} [data-theme="dark"] a{color:var(--gold-light);}
"""

THEME_TOGGLE_JS = """
<script>
(function(){
  var saved = localStorage.getItem('lcf-theme') ||
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', saved);
  window.lcfToggleTheme = function(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('lcf-theme', next);
  };
})();
</script>"""

# Compact inline brand mark used across pages (see /branding/logo.svg for full lockup)
_BRAND_SVG_SMALL = """<svg viewBox="0 0 70 70" xmlns="http://www.w3.org/2000/svg" style="width:40px;height:40px;">
  <title>Laxmi Chit Fund — Trust Engineered. Mostly.</title>
  <circle cx="35" cy="35" r="33" fill="#0d2340"/>
  <circle cx="35" cy="35" r="33" fill="none" stroke="#c9a227" stroke-width="2.5"/>
  <rect x="20" y="38" width="7" height="14" rx="1.5" fill="#c9a227"/>
  <rect x="30" y="30" width="7" height="22" rx="1.5" fill="#c9a227"/>
  <rect x="40" y="20" width="7" height="32" rx="1.5" fill="#e6c667"/>
  <circle cx="49" cy="17" r="4.2" fill="#c9a227"/>
</svg>"""

_BRAND_SVG_LARGE = """<svg viewBox="0 0 70 70" xmlns="http://www.w3.org/2000/svg" style="width:70px;height:70px;flex-shrink:0;">
  <title>Laxmi Chit Fund — Trust Engineered. Mostly.</title>
  <circle cx="35" cy="35" r="33" fill="#0d2340" stroke="#8a6d15" stroke-width="1"/>
  <circle cx="35" cy="35" r="27" fill="none" stroke="#c9a227" stroke-width="1.5"/>
  <rect x="21" y="38" width="6" height="12" rx="1.2" fill="#c9a227"/>
  <rect x="30" y="31" width="6" height="19" rx="1.2" fill="#c9a227"/>
  <rect x="39" y="22" width="6" height="28" rx="1.2" fill="#e6c667"/>
  <circle cx="47" cy="19" r="3.6" fill="#c9a227"/>
</svg>"""

# Easter-egg taglines, rotated quietly in footers / loading states
_TAGLINES = [
    "Approved by the Department of Extremely Questionable Investments.",
    "Our uptime is 99.999999%* (*according to our intern).",
    "Powered by Coffee, Panic &amp; YAML.",
    "Executive Decision Engine v0.0.1 — now with 12% fewer typos.",
    "Audited annually by someone, probably.",
    "Trust Engineered. Mostly.",
    "Synergizing stakeholder value since a Tuesday.",
    "Blockchain-adjacent. Cloud-native. Personality-optional.",
    "Leveraging best-in-class buzzwords for maximum vibes.",
    "Our disaster recovery plan is also a disaster.",
    "Now with 40% more bar charts.",
    "Compliance is a journey, not a destination. Mostly a journey.",
]

# Fake compliance/certification badges — decorative only, no real standards implied
COMPLIANCE_BADGES = [
    ("ISO&nbsp;9001&frac12;", "Certified"),
    ("SOC&nbsp;2 (Type&nbsp;&frac34;)", "Attested"),
    ("PCI-DSS-ish", "Compliant*"),
    ("Six&nbsp;Sigma", "Approximately"),
]

# Fictional internal business units — humor lives in the org chart, not the forms
BUSINESS_UNITS = [
    ("Dept. of Extremely Questionable Investments", "Strategy",  "Thriving"),
    ("Ministry of Synergy &amp; Vibes",              "People",    "Aligned"),
    ("Office of Aggressive Optimism",                "Comms",     "Bullish"),
    ("Compliance &amp; Plausible Deniability Div.",  "Legal",     "Reviewing"),
    ("Dept. of Circular Reporting",                  "Analytics", "Recursive"),
    ("Innovation Theater Group",                     "Product",   "Disrupting"),
]

def _compliance_strip():
    chips = "".join(
        f'<span class="cert-chip" title="{label} — purely decorative, not a real certification">'
        f'<b>{name}</b>&nbsp;{label}</span>' for name, label in COMPLIANCE_BADGES
    )
    return f'<div class="cert-strip">{chips}</div>'

def _tagline():
    return random.choice(_TAGLINES)

# ── HTML Templates ─────────────────────────────────────────────────────────────
_THEME_CSS_ESCAPED = _THEME_CSS.replace("{", "{{").replace("}", "}}")

_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Laxmi Chit Fund — Internal Systems — {title}</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>""" + _THEME_CSS_ESCAPED + """
.topbar{{background:linear-gradient(90deg,var(--navy),var(--navy-2));color:#fff;padding:0 24px;height:52px;display:flex;align-items:center;justify-content:space-between;}}
.topbar .brand{{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:700;letter-spacing:.3px;}}
.topbar nav a{{color:rgba(255,255,255,.85);text-decoration:none;padding:6px 12px;border-radius:4px;font-size:12px;margin-left:2px;transition:background .15s;}}
.topbar nav a:hover,.topbar nav a.active{{background:rgba(255,255,255,.18);}}
.topbar .user{{display:flex;align-items:center;gap:10px;font-size:12px;}}
.topbar .user .av{{width:26px;height:26px;background:var(--gold);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:bold;color:var(--navy);}}
.topbar .user a{{color:rgba(255,255,255,.85);text-decoration:none;padding:4px 10px;border:1px solid rgba(255,255,255,.35);border-radius:4px;font-size:11px;}}
.theme-btn{{background:none;border:1px solid rgba(255,255,255,.35);color:#fff;border-radius:4px;padding:4px 9px;font-size:11px;cursor:pointer;}}
.breadcrumb{{background:var(--card);border-bottom:1px solid var(--border);padding:7px 24px;font-size:12px;color:var(--muted);}}
main{{padding:22px 24px 40px;max-width:1280px;margin:0 auto;}}
h1{{font-size:19px;color:var(--navy);margin-bottom:4px;font-weight:700;}}
[data-theme="dark"] h1{{color:var(--gold-light);}}
.sub{{font-size:11.5px;color:var(--muted);margin-bottom:18px;}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:6px;font-size:12.5px;overflow:hidden;}}
th{{background:var(--navy);color:#fff;padding:9px 10px;text-align:left;font-weight:600;font-size:11px;letter-spacing:.3px;}}
td{{padding:9px 10px;border-bottom:1px solid var(--border);color:var(--text);}}
tr:hover td{{background:rgba(201,162,39,.06);}}
tr:last-child td{{border-bottom:none;}}
.badge{{display:inline-flex;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;}}
.badge.ok{{background:rgba(31,157,99,.12);color:var(--ok);}}
.badge.warn{{background:rgba(200,129,26,.12);color:var(--warn);}}
.badge.err{{background:rgba(209,72,63,.12);color:var(--err);}}
.badge.info{{background:rgba(18,58,102,.12);color:var(--info);}}
[data-theme="dark"] .badge.info{{color:var(--gold-light);}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px 20px;margin-bottom:18px;box-shadow:0 1px 3px rgba(10,20,40,.05);}}
.card h2{{font-size:13.5px;font-weight:700;color:var(--text);margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px;}}
.kpi{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:15px 17px;transition:transform .15s;}}
.kpi:hover{{transform:translateY(-2px);}}
.kpi.b{{border-top:3px solid var(--navy-2);}}.kpi.g{{border-top:3px solid var(--ok);}}
.kpi.o{{border-top:3px solid var(--warn);}}.kpi.r{{border-top:3px solid var(--err);}}
.kpi h3{{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}}
.kpi .val{{font-size:25px;font-weight:700;color:var(--text);}}
.kpi .delta{{font-size:10px;margin-top:3px;color:var(--muted);}}
.two-col{{display:grid;grid-template-columns:2fr 1fr;gap:16px;}}
.form-group{{margin-bottom:14px;}}
.form-group label{{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;font-weight:600;}}
.form-group input,.form-group select,textarea{{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:5px;font-size:13px;background:var(--card);color:var(--text);}}
.btn{{padding:8px 20px;border:none;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;transition:filter .15s;}}
.btn:hover{{filter:brightness(1.08);}}
.btn.primary{{background:var(--navy-2);color:#fff;}}.btn.danger{{background:var(--err);color:#fff;}}
.btn.gold{{background:var(--gold);color:var(--navy);}}
.search-bar{{display:flex;gap:8px;margin-bottom:14px;}}
.search-bar input{{flex:1;padding:8px 10px;border:1px solid var(--border);border-radius:5px;font-size:13px;background:var(--card);color:var(--text);}}
.alert{{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;}}
.alert.err{{background:rgba(209,72,63,.08);border:1px solid rgba(209,72,63,.35);color:var(--err);border-left:3px solid var(--err);}}
.alert.ok{{background:rgba(31,157,99,.08);border:1px solid rgba(31,157,99,.35);color:var(--ok);border-left:3px solid var(--ok);}}
footer{{background:var(--card);border-top:2px solid var(--gold);padding:12px 24px;text-align:center;font-size:11px;color:var(--muted);margin-top:40px;}}
.cert-strip{{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:8px 0 4px;}}
.cert-chip{{font-size:10px;background:rgba(201,162,39,.1);border:1px solid rgba(201,162,39,.4);color:var(--gold-dim);padding:3px 9px;border-radius:12px;cursor:help;}}
[data-theme="dark"] .cert-chip{{color:var(--gold-light);}}
@keyframes lcfFadeUp{{from{{opacity:0;transform:translateY(6px);}}to{{opacity:1;transform:translateY(0);}}}}
.card,.kpi{{animation:lcfFadeUp .35s ease both;}}
.kpi:nth-child(2){{animation-delay:.05s;}} .kpi:nth-child(3){{animation-delay:.1s;}} .kpi:nth-child(4){{animation-delay:.15s;}}
.buzzword-ticker{{font-size:11.5px;color:var(--gold-dim);font-style:italic;min-height:16px;}}
[data-theme="dark"] .buzzword-ticker{{color:var(--gold-light);}}
footer .tag{{display:block;font-style:italic;opacity:.75;margin-top:2px;}}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">""" + _BRAND_SVG_SMALL + """ Laxmi Chit Fund <span style="opacity:.6;font-weight:400;">| Internal Systems</span></div>
  <nav>
    <a href="/admin/dashboard"     {d}>Dashboard</a>
    <a href="/admin/branches"      {s}>Branch Admin</a>
    <a href="/admin/employees"     {f}>Employees</a>
    <a href="/admin/infrastructure"{r}>Infrastructure</a>
    <a href="/admin/logs"          {rp}>Audit Logs</a>
    <a href="/admin/settings"      {st}>Server Config</a>
  </nav>
  <div class="user">
    <button class="theme-btn" onclick="lcfToggleTheme()">&#9788;/&#9789;</button>
    <div class="av">{av}</div>
    <span>{uname}</span>
    <a href="/admin/logout">Logout</a>
  </div>
</div>
<div class="breadcrumb">Internal &rsaquo; {title}</div>
<main>"""

_FOOTER = """</main>
<footer>&copy; Laxmi Chit Fund — Internal Use Only. This system is fictional and exists solely as a security honeypot.
<span class="tag">{tag}</span></footer>
</body></html>"""

def _nav(active, uname):
    keys = ["d","s","f","r","rp","st"]
    vals = {k: "" for k in keys}
    if active in vals:
        vals[active] = 'class="active"'
    return vals, uname[0].upper() if uname else "A", uname or "admin"

_CONSOLE_EASTER_EGG = """<script>
console.log("%cWell, aren't you curious.", "font-weight:bold;color:#c9a227;font-size:14px;");
console.log("This is a fictional internal system used purely for honeypot research. Nothing here is a real bank.");
</script>"""

def _page(title, active, uname, content):
    nav, av, un = _nav(active, uname)
    header = _HEADER.format(title=title, av=av, uname=un, **nav)
    footer = _FOOTER.format(tag=_tagline())
    footer = footer.replace(
        '<span class="tag">',
        _compliance_strip() + '<span class="tag">'
    )
    # Insert theme-toggle script + console easter egg just before </body></html>
    footer = footer.replace(
        "</body></html>",
        THEME_TOGGLE_JS + _CONSOLE_EASTER_EGG + "\n</body></html>"
    )
    return header + content + footer

# ── Login pages ───────────────────────────────────────────────────────────────
def _login_shell(body_html):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Laxmi Chit Fund — IT Administrator Login</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>{_THEME_CSS}
body{{background:var(--bg);}}
.topbar{{background:var(--card);border-bottom:1px solid var(--border);padding:8px 24px;text-align:right;font-size:12px;color:var(--muted);}}
.header{{background:var(--card);padding:14px 40px;display:flex;align-items:center;gap:20px;border-bottom:1px solid var(--border);}}
.header h1{{font-size:19px;font-weight:700;color:var(--navy);}}
[data-theme="dark"] .header h1{{color:var(--gold-light);}}
.header p{{font-size:11px;color:var(--gold-dim);font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-top:2px;}}
.titlebar{{background:linear-gradient(90deg,var(--navy),var(--navy-2));color:#fff;text-align:center;padding:14px;font-size:20px;font-weight:700;}}
.main{{display:flex;justify-content:center;padding:44px 20px 90px;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:32px 40px;width:480px;box-shadow:0 4px 18px rgba(10,20,40,.08);}}
.card h2{{text-align:center;font-size:17px;color:var(--text);margin-bottom:22px;font-weight:700;}}
.row{{display:flex;align-items:center;margin-bottom:18px;gap:12px;}}
.row label{{width:150px;font-size:13.5px;color:var(--text);text-align:right;font-weight:600;flex-shrink:0;}}
.row .static{{font-size:14px;color:var(--muted);padding:7px 0;}}
.row input{{flex:1;padding:8px 10px;border:1px solid var(--border);border-radius:5px;font-size:14px;background:var(--bg);color:var(--text);outline:none;}}
.row input:focus{{border-color:var(--gold);}}
.captcha-wrap{{display:flex;align-items:center;gap:10px;}}
.captcha-wrap input{{width:120px;}}
.captcha-img{{padding:6px 14px;background:var(--navy);border:2px solid var(--gold);border-radius:5px;font:bold italic 16px 'Courier New',monospace;color:var(--gold-light);letter-spacing:4px;user-select:none;}}
.btn-row{{display:flex;justify-content:center;margin-top:8px;}}
.btn{{padding:9px 34px;background:linear-gradient(180deg,var(--gold-light),var(--gold));color:var(--navy);border:none;border-radius:5px;font-size:14px;font-weight:700;cursor:pointer;}}
.alert{{padding:9px 14px;border-radius:5px;margin-bottom:14px;font-size:13px;text-align:center;}}
.alert.err{{background:rgba(209,72,63,.1);border:1px solid rgba(209,72,63,.4);color:var(--err);}}
.theme-btn{{background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:3px 9px;font-size:11px;cursor:pointer;margin-left:8px;}}
footer{{background:var(--card);border-top:2px solid var(--gold);padding:12px;text-align:center;font-size:11.5px;color:var(--muted);position:fixed;bottom:0;left:0;right:0;}}
footer .tag{{display:block;font-style:italic;opacity:.7;margin-top:2px;}}
</style></head><body>
<div class="topbar">Internal Network Only &nbsp;|&nbsp; <button class="theme-btn" onclick="lcfToggleTheme()">Toggle theme</button></div>
<div class="header">
  {_BRAND_SVG_LARGE}
  <div>
    <h1>LAXMI CHIT FUND</h1>
    <p>Internal Systems &mdash; Authorized Personnel Only</p>
  </div>
</div>
<div class="titlebar">IT Administrator Login</div>
<div class="main"><div class="card">
{body_html}
</div></div>
<footer>&copy; Laxmi Chit Fund — Internal Use Only. Fictional entity; honeypot research system.
<span class="tag">{_tagline()}</span></footer>{THEME_TOGGLE_JS}
</body></html>"""

def _step1_html(error=""):
    err_blk = f'<div class="alert err">{error}</div>' if error else ""
    body = f"""  <h2>Administrator Sign-In</h2>
  {err_blk}
  <form method="POST" action="/admin/step1">
    <div class="row"><label>Username:</label>
      <input type="text" name="username" autocomplete="off" autofocus/></div>
    <div class="btn-row"><button class="btn" type="submit">Next</button></div>
  </form>"""
    return _login_shell(body)

def _step2_html(username, captcha_code, error=""):
    err_blk = f'<div class="alert err">{error}</div>' if error else ""
    body = f"""  <h2>Administrator Sign-In</h2>
  {err_blk}
  <form method="POST" action="/admin/login">
    <input type="hidden" name="username" value="{username}"/>
    <div class="row"><label>Username:</label><div class="static">{username}</div></div>
    <div class="row"><label>Password:</label>
      <input type="password" name="password" autocomplete="off" autofocus/></div>
    <div class="row"><label>Security Code:</label>
      <div class="captcha-wrap">
        <input type="text" name="captcha" autocomplete="off"/>
        <div class="captcha-img">{captcha_code}</div>
      </div></div>
    <div class="btn-row"><button class="btn" type="submit">Sign In</button></div>
  </form>"""
    return _login_shell(body)

# ── Fake SQL error ─────────────────────────────────────────────────────────────
def _sql_error(payload):
    return f"""<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>
<body style="font-family:Courier New;background:#fff;padding:30px;">
<h2 style="color:#cc0000;">Microsoft OLE DB Provider for SQL Server error '80040e14'</h2>
<p>Unclosed quotation mark after the character string '{payload}'.</p>
<p>/admin/search.aspx, line 47</p>
<hr/>
<p style="font-size:11px;color:#888;">ASP.NET v4.0.30319 | IIS/10.0 | Laxmi Ledger vNext (Build 2026.07)</p>
</body></html>"""

# ── robots.txt ────────────────────────────────────────────────────────────────
ROBOTS_TXT = """User-agent: *
Disallow: /backup/
Disallow: /private/
Disallow: /admin_backup/
Disallow: /db_dump/
Disallow: /config/
Disallow: /admin/database
Disallow: /admin/export
Disallow: /admin/logs
Disallow: /.env
Disallow: /wp-admin/
Disallow: /phpmyadmin/
"""

# ── Bait directory files ──────────────────────────────────────────────────────
BAIT_FILES = {
    "/backup/backup_2024.sql":      b"-- MySQL dump 10.13\n-- Server: localhost\nCREATE TABLE `users` (\n  `id` int(11) NOT NULL,\n  `username` varchar(50),\n  `password_hash` varchar(255)\n);\n",
    "/backup/users_dump.sql":       b"-- Users table dump\nINSERT INTO users VALUES (1,'admin','$2y$10$TRUNCATED_FOR_SECURITY');\n",
    "/backup/admin_credentials.xlsx": b"PK\x03\x04[ENCRYPTED_EXCEL_BINARY_PLACEHOLDER]",
    "/config/db.php":               b"<?php\n// Database configuration\n$db_host = 'localhost';\n$db_name = 'lcf_ledger';\n$db_user = 'lcf_admin';\n$db_pass = '***REMOVED***';\n?>",
    "/private/notes.txt":           b"Admin notes - CONFIDENTIAL\nBackup password rotated on 01-Jan-2026\nMysql root: see keepass vault\n",
    "/db_dump/lcf_core_march2026.sql": b"-- Full DB dump March 2026\n-- WARNING: Contains internal data\n",
    "/admin_backup/portal_backup.zip": b"PK[ZIP_BINARY_PLACEHOLDER - ACCESS_DENIED]",
    "/.env":
        b"APP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://laxmichitfund.internal\n\n"
        b"DB_CONNECTION=mysql\nDB_HOST=localhost\nDB_PORT=3306\n"
        b"DB_DATABASE=lcf_ledger\nDB_USERNAME=lcf_admin\nDB_PASSWORD=***REMOVED***\n\n"
        b"REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=***REMOVED***\nREDIS_PORT=6379\n\n"
        b"JWT_SECRET=***REMOVED***\nJWT_EXPIRY=3600\n"
        b"AWS_ACCESS_KEY_ID=***REMOVED***\nAWS_SECRET_ACCESS_KEY=***REMOVED***\nAWS_REGION=ap-south-1\n",

    "/backup/lcf_ledger_backup.sql":
        b"-- MySQL dump 10.19  Distrib 8.0.32\n"
        b"-- Host: localhost  Database: lcf_ledger\n"
        b"-- Dump date: 2026-07-01 03:00:04\n"
        b"CREATE TABLE `users` (`id` int, `employee_no` varchar(20), `password_hash` varchar(255));\n"
        b"INSERT INTO `users` VALUES (1,'admin','$2y$10$TRUNCATED'),(2,'LCF-1042','$2y$10$TRUNCATED');\n",

    "/backup/employee_records_2024.csv":
        b"employee_no,name,email,branch_code,dept,rating\n"
        b"LCF-1042,Rahul Patel,r.patel@laxmichitfund.internal,BR-014,Ops,8.4\n"
        b"LCF-1043,Priya Shah,p.shah@laxmichitfund.internal,BR-014,Ops,9.1\n"
        b"LCF-3011,Amit Kumar,a.kumar@laxmichitfund.internal,HQ,IT,7.9\n",

    "/config/database.yml":
        b"production:\n  adapter: mysql2\n  host: localhost\n"
        b"  database: lcf_ledger\n  username: lcf_admin\n  password: ***REMOVED***\n",

    "/config/config.ini":
        b"[database]\nhost=localhost\nport=3306\nname=lcf_ledger\n"
        b"user=lcf_admin\npassword=***REMOVED***\n\n"
        b"[redis]\nhost=127.0.0.1\nport=6379\npassword=***REMOVED***\n",
}

# ── Upload page ───────────────────────────────────────────────────────────────
UPLOAD_PAGE = """<!DOCTYPE html><html><head><title>Laxmi Chit Fund — Internal Upload</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>body{{font-family:Arial;background:#f4f6fb;padding:40px;}}
.card{{background:#fff;border:1px solid #dbe2ef;padding:30px;max-width:500px;border-radius:8px;}}
h2{{color:#0d2340;margin-bottom:20px;}}
input[type=file]{{margin-bottom:14px;display:block;}}
button{{padding:9px 26px;background:#c9a227;color:#0d2340;border:none;border-radius:5px;cursor:pointer;font-weight:700;}}
.ok{{color:#1f9d63;font-weight:bold;margin-top:14px;}}
</style></head><body>
<div class="card"><h2>Internal File Upload</h2>
{msg}
<form method="POST" action="/admin/upload.aspx" enctype="multipart/form-data">
  <input type="file" name="file"/>
  <button type="submit">Upload File</button>
</form></div></body></html>"""

# ── Static branding assets served by the honeypot itself ─────────────────────
FAVICON_SVG = b"""<svg viewBox="0 0 70 70" xmlns="http://www.w3.org/2000/svg">
  <circle cx="35" cy="35" r="33" fill="#0d2340"/>
  <circle cx="35" cy="35" r="33" fill="none" stroke="#c9a227" stroke-width="2.5"/>
  <rect x="20" y="38" width="7" height="14" rx="1.5" fill="#c9a227"/>
  <rect x="30" y="30" width="7" height="22" rx="1.5" fill="#c9a227"/>
  <rect x="40" y="20" width="7" height="32" rx="1.5" fill="#e6c667"/>
  <circle cx="49" cy="17" r="4.2" fill="#c9a227"/>
</svg>"""

MAINTENANCE_PAGE = """<!DOCTYPE html><html><head><title>Laxmi Chit Fund — Maintenance</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>body{font-family:Arial;background:#0d2340;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;}
.box{max-width:480px;} h1{color:#e6c667;} p{color:#cdd6ea;font-size:14px;}
.tag{margin-top:18px;font-style:italic;opacity:.6;font-size:12px;}</style></head>
<body><div class="box"><h1>Scheduled Maintenance</h1>
<p>Core Ledger services are temporarily unavailable while we perform routine maintenance.</p>
<p class="tag">Powered by Coffee, Panic &amp; YAML.</p></div></body></html>"""

SESSION_EXPIRED_PAGE = """<!DOCTYPE html><html><head><title>Laxmi Chit Fund — Session Expired</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>body{font-family:Arial;background:#f4f6fb;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.card{background:#fff;border:1px solid #dbe2ef;border-radius:8px;padding:36px 44px;text-align:center;box-shadow:0 4px 18px rgba(10,20,40,.08);}
h1{color:#0d2340;} a{color:#123a66;}</style></head>
<body><div class="card"><h1>Session Expired</h1>
<p>Your administrator session has timed out for security reasons.</p>
<p><a href="/admin/login.aspx">Return to sign-in</a></p></div></body></html>"""

NOT_FOUND_PAGE = """<!DOCTYPE html><html><head><title>404 — Laxmi Chit Fund Internal</title>
<link rel="icon" href="/branding/favicon.svg" type="image/svg+xml"/>
<style>body{font-family:Arial;background:#f4f6fb;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;}
h1{color:#0d2340;font-size:52px;margin-bottom:0;} p{color:#64708a;}</style></head>
<body><div><h1>404</h1><p>The requested internal resource could not be found.</p></div></body></html>"""

# ── Request handler ────────────────────────────────────────────────────────────
class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _ip(self):  return self.client_address[0]
    def _ua(self):  return self.headers.get("User-Agent", "")
    def _cookies(self): return self.headers.get("Cookie", "")
    def _sid(self):
        _, sess = _get_session_from_cookie(self._cookies())
        return sess

    def _log(self, event, sid="", **kw):
        tool = hp_log.detect_scanner(self._ua(), self.path,
                                      kw.get("payload", ""))
        if tool:
            kw["tool"] = tool
            kw["scanner_detected"] = True
            alerts.check_scanner(tool, self._ip(), "HTTP", sid)
        hp_log.log(event, self._ip(), "HTTP", sid,
                   port=self.server.server_address[1],
                   user_agent=self._ua(), path=self.path, **kw)

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        # Realistic anti-detection delay (50-250ms)
        time.sleep(random.uniform(0.2, 1.5))
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(body))
        # Rotate server banners
        banners = [
            ("Microsoft-IIS/10.0", "ASP.NET"),
            ("Apache/2.4.51 (Win64)", "PHP/8.0.12"),
            ("nginx/1.21.6",  ""),
        ]
        srv, powered = random.choice(banners)
        self.send_header("Server", srv)
        if powered:
            self.send_header("X-Powered-By", powered)
        self.send_header("X-AspNet-Version", "4.0.30319")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()

    def _require_auth(self):
        """Return (token, sess) or redirect. Returns (None,None) if redirected."""
        cookie = self._cookies()
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("ASP.NET_SessionId="):
                token = part.split("=", 1)[1]
                sess = _validate_session(token)
                if sess:
                    return token, sess
        self._redirect("/admin/login.aspx")
        return None, None

    # ── Pages ──────────────────────────────────────────────────────────────────
    def _dashboard(self, uname):
        units_rows = "".join(
            f"<tr><td>{u[0]}</td><td>{u[1]}</td><td><span class='badge info'>{u[2]}</span></td></tr>"
            for u in BUSINESS_UNITS)
        content = """
<h1>Core Banking Operations Dashboard</h1>
<div class="sub">Display-only overview &mdash; Welcome back, {uname}. Last login: today at 08:41 from 192.168.1.1</div>
<div class="buzzword-ticker" id="lcfBuzz">Leveraging synergistic ledger architecture for hyper-scalable stakeholder value&hellip;</div>
<div class="kpi-grid">
  <div class="kpi b"><h3>Branches Online</h3><div class="val">148 / 152</div><div class="delta">&#8593; 2 recovered overnight</div></div>
  <div class="kpi g"><h3>Ledger Txns Processed</h3><div class="val">2.41M</div><div class="delta">&#8593; 3.1% vs yesterday</div></div>
  <div class="kpi o"><h3>Open Incidents</h3><div class="val">3</div><div class="delta">&#9888; See Infrastructure</div></div>
  <div class="kpi r"><h3>Failed Auth (24h)</h3><div class="val">217</div><div class="delta">&#9679; Mostly VPN gateway</div></div>
</div>
<div class="two-col">
<div class="card"><h2>Recent Console Logins</h2>
<table><thead><tr><th>User</th><th>IP Address</th><th>Time</th><th>Status</th></tr></thead>
<tbody>
  <tr><td>{uname}</td><td>192.168.1.1</td><td>Just now</td><td><span class="badge ok">SUCCESS</span></td></tr>
  <tr><td>{uname}</td><td>10.0.2.15</td><td>2h ago</td><td><span class="badge ok">SUCCESS</span></td></tr>
  <tr><td>root</td><td>203.0.113.42</td><td>5h ago</td><td><span class="badge err">FAILED</span></td></tr>
  <tr><td>administrator</td><td>185.220.101.5</td><td>6h ago</td><td><span class="badge err">FAILED</span></td></tr>
  <tr><td>guest</td><td>198.51.100.7</td><td>7h ago</td><td><span class="badge info">GUEST</span></td></tr>
</tbody></table></div>
<div class="card"><h2>Service Status</h2>
  <table><tbody>
    <tr><td>Core Ledger</td><td><span class="badge ok">ONLINE</span></td></tr>
    <tr><td>Database Cluster</td><td><span class="badge ok">ONLINE</span></td></tr>
    <tr><td>FTP Relay</td><td><span class="badge ok">ONLINE</span></td></tr>
    <tr><td>SSH Bastion</td><td><span class="badge ok">ONLINE</span></td></tr>
    <tr><td>Backup Service</td><td><span class="badge warn">DEGRADED</span></td></tr>
    <tr><td>Mail Relay</td><td><span class="badge err">OFFLINE</span></td></tr>
  </tbody></table>
</div></div>
<div class="card"><h2>Business Units</h2>
<table><thead><tr><th>Unit</th><th>Function</th><th>Vibe Check</th></tr></thead>
<tbody>{units_rows}</tbody></table></div>
<script>
(function(){{
  var words = [
    "Leveraging synergistic ledger architecture for hyper-scalable stakeholder value&hellip;",
    "Circling back on core banking KPIs to unlock actionable synergy&hellip;",
    "Operationalizing our north-star metrics across all verticals&hellip;",
    "Ideating a paradigm shift in customer-adjacent value streams&hellip;",
    "Right-sizing the roadmap for maximum bandwidth utilization&hellip;"
  ];
  var el = document.getElementById('lcfBuzz');
  var i = 0;
  if (el) setInterval(function(){{ i = (i+1) % words.length; el.innerHTML = words[i]; }}, 4000);
}})();
</script>""".format(uname=uname, units_rows=units_rows)
        return _page("Core Banking Operations Dashboard", "d", uname, content)

    def _branches_page(self, uname, q=""):
        rows = "".join(
            f"<tr><td>{b[0]}</td><td>{b[1]}</td><td>{b[2]}</td>"
            f"<td><span class='badge {'ok' if b[3]=='Online' else ('warn' if b[3]=='Degraded' else 'err')}'>{b[3].upper()}</span></td>"
            f"<td><span class='badge {'ok' if b[4]=='Active' else 'warn'}'>{b[4]}</span></td></tr>"
            for b in FAKE_BRANCHES if not q or q.lower() in str(b).lower()
        )
        content = f"""<h1>Branch Administration</h1>
<div class="sub">Manage registered branches &mdash; Total: {len(FAKE_BRANCHES)}</div>
<div class="search-bar">
  <form method="GET" action="/admin/search" style="display:flex;gap:8px;width:100%;">
    <input type="text" name="q" placeholder="Search by branch code, name, region..." value="{q}"/>
    <button class="btn primary" type="submit">Search</button>
  </form>
</div>
<table><thead><tr><th>Branch Code</th><th>Name</th><th>Region</th><th>Network</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="font-size:11px;color:var(--muted);margin-top:8px;">Showing {len(FAKE_BRANCHES)} records.
&nbsp;<a href="/admin/export?file=branches.csv">Export CSV</a></p>"""
        return _page("Branch Administration", "s", uname, content)

    def _employees_page(self, uname):
        rows = "".join(
            f"<tr><td>{e[0]}</td><td>{e[1]}</td><td>{e[2]}</td><td>{e[3]}</td>"
            f"<td><span class='badge {'ok' if e[4]=='Active' else 'warn'}'>{e[4]}</span></td></tr>"
            for e in FAKE_EMPLOYEES)
        content = f"""<h1>Employee Portal</h1>
<div class="sub">Internal staff directory &mdash; Total: {len(FAKE_EMPLOYEES)}</div>
<table><thead><tr><th>Employee No.</th><th>Name</th><th>Department</th><th>Role</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>"""
        return _page("Employee Portal", "f", uname, content)

    def _infrastructure_page(self, uname, node=""):
        rows = "".join(
            f"<tr><td>{s[0]}</td><td>{s[1]}</td><td style='font-family:monospace'>{s[2]}</td>"
            f"<td><span class='badge {'ok' if s[3]=='Online' else 'warn'}'>{s[3].upper()}</span></td><td>{s[4]}</td></tr>"
            for s in FAKE_SERVERS if not node or node in s[0])
        content = f"""<h1>Infrastructure Monitoring</h1>
<div class="sub">Node health &amp; network status</div>
<div class="search-bar">
  <form method="GET" action="/admin/user" style="display:flex;gap:8px;width:100%;">
    <input type="text" name="id" placeholder="Node name..." value="{node}"/>
    <button class="btn primary" type="submit">Filter</button>
  </form>
</div>
<table><thead><tr><th>Node</th><th>Role</th><th>Internal IP</th><th>Status</th><th>Load</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="card" style="margin-top:16px;"><h2>Quick Links</h2>
<p style="font-size:12.5px;line-height:2;">
<a href="/admin/network">&#8594; Network Status</a><br/>
<a href="/admin/database">&#8594; Database Administration</a><br/>
<a href="/admin/security">&#8594; Security Operations Console</a><br/>
<a href="/admin/backups">&#8594; Backup Management</a><br/>
<a href="/admin/documents">&#8594; Internal Documents</a>
</p></div>"""
        return _page("Infrastructure Monitoring", "r", uname, content)

    def _settings_page(self, uname):
        content = """<h1>Server Configuration</h1>
<div class="card"><h2>Database Connection</h2>
<div class="form-group"><label>DB Host</label><input type="text" value="localhost" readonly/></div>
<div class="form-group"><label>DB Name</label><input type="text" value="lcf_ledger_prod" readonly/></div>
<div class="form-group"><label>DB User</label><input type="text" value="lcf_admin" readonly/></div>
<div class="form-group"><label>DB Password</label><input type="password" value="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;" readonly/></div>
</div>
<div class="card"><h2>SMTP Configuration</h2>
<div class="form-group"><label>SMTP Host</label><input type="text" value="mail.laxmichitfund.internal"/></div>
<div class="form-group"><label>SMTP Port</label><input type="text" value="587"/></div>
<div class="form-group"><label>Username</label><input type="text" value="noreply@laxmichitfund.internal"/></div>
</div>"""
        return _page("Server Configuration", "st", uname, content)

    def _database_page(self, uname):
        content = """<h1>Database Administration</h1>
<div class="alert err">&#9888; Direct database access is restricted. All queries are logged and audited.</div>
<div class="card"><h2>Quick Query</h2>
<form method="GET" action="/admin/search">
<div class="form-group"><label>SQL Query</label>
<textarea name="q" style="height:80px;font-family:monospace;font-size:12px;"
  placeholder="SELECT * FROM branches WHERE ..."></textarea></div>
<button class="btn primary" type="submit">Execute</button>
</form></div>
<div class="card"><h2>Table Overview</h2>
<table><thead><tr><th>Table</th><th>Rows</th><th>Size</th><th>Last Updated</th></tr></thead>
<tbody>
<tr><td>ledger_accounts</td><td>1,244,470</td><td>148 MB</td><td>2026-07-06</td></tr>
<tr><td>transactions_2026</td><td>8,923,041</td><td>2.1 GB</td><td>2026-07-06</td></tr>
<tr><td>employees</td><td>4,830</td><td>2.1 MB</td><td>2026-07-01</td></tr>
<tr><td>branches</td><td>152</td><td>0.4 MB</td><td>2026-06-28</td></tr>
</tbody></table></div>"""
        return _page("Database Administration", "r", uname, content)

    def _security_page(self, uname):
        rows = "".join(
            f"<tr><td>{i[0]}</td><td>{i[1]}</td>"
            f"<td><span class='badge {'err' if i[2]=='High' else ('warn' if i[2]=='Medium' else 'info')}'>{i[2].upper()}</span></td>"
            f"<td>{i[3]}</td></tr>" for i in FAKE_INCIDENTS)
        content = f"""<h1>Security Operations Console</h1>
<div class="sub">Executive Decision Engine v0.0.1 &mdash; open incidents &amp; blocked sources</div>
<div class="card"><h2>Open Incidents</h2>
<table><thead><tr><th>ID</th><th>Summary</th><th>Severity</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<div class="card"><h2>Recently Blocked IPs</h2>
<table><thead><tr><th>IP</th><th>Reason</th><th>Blocked At</th></tr></thead>
<tbody>
<tr><td>203.0.113.42</td><td>Repeated failed logins</td><td>2026-07-06 22:14</td></tr>
<tr><td>185.220.101.5</td><td>Tor exit node</td><td>2026-07-06 21:02</td></tr>
</tbody></table></div>"""
        return _page("Security Operations Console", "r", uname, content)

    def _backups_page(self, uname):
        rows = "".join(
            f"<tr><td>{b[0]}</td><td>{b[1]}</td>"
            f"<td><span class='badge {'ok' if b[2]=='SUCCESS' else 'err'}'>{b[2]}</span></td><td>{b[3]}</td></tr>"
            for b in FAKE_BACKUPS)
        content = f"""<h1>Backup Management</h1>
<div class="sub">Nightly job status</div>
<table><thead><tr><th>Job</th><th>Completed</th><th>Status</th><th>Size</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="font-size:11px;color:var(--muted);margin-top:8px;">
<a href="/admin/export?file=backup_manifest.json">Download manifest</a></p>"""
        return _page("Backup Management", "r", uname, content)

    def _documents_page(self, uname):
        rows = "".join(
            f"<tr><td>{d[0]}</td><td>{d[1]}</td><td>{d[2]}</td><td>{d[3]}</td></tr>"
            for d in FAKE_DOCS)
        content = f"""<h1>Internal Documents</h1>
<div class="sub">Internal Wiki &mdash; policies &amp; runbooks (display only)</div>
<table><thead><tr><th>Doc ID</th><th>Title</th><th>Owner</th><th>Version</th></tr></thead>
<tbody>{rows}</tbody></table>"""
        return _page("Internal Documents", "r", uname, content)

    def _network_page(self, uname):
        content = """<h1>Network Status</h1>
<div class="sub">Site-to-site links &amp; edge status</div>
<div class="card"><h2>Branch VPN Tunnels</h2>
<table><thead><tr><th>Tunnel</th><th>Peer</th><th>Status</th><th>Latency</th></tr></thead>
<tbody>
<tr><td>vpn-br014</td><td>Vastrapur Branch</td><td><span class="badge ok">UP</span></td><td>12ms</td></tr>
<tr><td>vpn-br045</td><td>Rajkot Branch</td><td><span class="badge warn">FLAPPING</span></td><td>88ms</td></tr>
<tr><td>vpn-br070</td><td>Pune Kothrud</td><td><span class="badge err">DOWN</span></td><td>&mdash;</td></tr>
</tbody></table></div>"""
        return _page("Network Status", "r", uname, content)

    def _logs_page(self, uname, date_filter=""):
        rows = "".join(
            f"<tr><td style='font-family:monospace;font-size:11px'>{l[0]}</td>"
            f"<td>{l[1]}</td><td style='font-family:monospace;font-size:11px'>{l[2]}</td>"
            f"<td><span class='badge {'ok' if l[3]=='200' else 'err'}'>{l[3]}</span></td>"
            f"<td style='font-size:11px;color:var(--muted)'>{l[4]}</td></tr>"
            for l in FAKE_LOGS)
        content = f"""<h1>Audit Logs</h1>
<div class="search-bar">
  <form method="GET" action="/admin/logs" style="display:flex;gap:8px;width:100%;">
    <input type="text" name="date" placeholder="Date filter (YYYY-MM-DD)..." value="{date_filter}"/>
    <button class="btn primary" type="submit">Filter</button>
    <a href="/admin/export?file=access_logs_{date_filter or '2026-07-06'}.txt"
       class="btn primary" style="text-decoration:none;padding:8px 20px;">Export</a>
  </form>
</div>
<table><thead><tr><th>Timestamp</th><th>IP</th><th>Request</th><th>Status</th><th>User-Agent</th></tr></thead>
<tbody>{rows}</tbody></table>"""
        return _page("Audit Logs", "rp", uname, content)

    # ── GET handler ────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)
        ip     = self._ip()

        self._log("GET")

        # ── robots.txt ──
        if path == "/robots.txt":
            self._send(200, ROBOTS_TXT, "text/plain")
            return

        # ── Branding assets ──
        if path in ("/branding/favicon.svg", "/favicon.svg", "/favicon.ico"):
            self._send(200, FAVICON_SVG, "image/svg+xml")
            return

        # ── Misc static decoy pages ──
        if path == "/maintenance":
            self._send(200, MAINTENANCE_PAGE)
            return
        if path == "/session-expired":
            self._send(200, SESSION_EXPIRED_PAGE)
            return

        # ── Login flow ──
        if path in ("/", "/admin", "/admin/login.aspx", "/login"):
            self._send(200, _step1_html())
            return

        # ── Bait directories ──
        if path in BAIT_FILES:
            self._log("BAIT_ACCESS", filename=path)
            alerts.check_http_path(path, self._ip(), self._sid() and self._cookies())
            alerts.trigger("BAIT_FILE_ACCESS", self._ip(), "HTTP",
                           detail=f"Bait file accessed: {path}", path=path)
            self._send(200, BAIT_FILES[path], "application/octet-stream")
            return

        if path in ("/backup", "/config", "/private", "/db_dump",
                    "/admin_backup", "/.env"):
            # Directory listing bait
            files = [k for k in BAIT_FILES if k.startswith(path + "/") or k == path]
            listing = "<br/>".join(f'<a href="{f}">{f}</a>' for f in files) or "No files"
            self._send(200, f"<html><body><h2>Index of {path}</h2>{listing}</body></html>")
            return

        # ── Upload page ──
        if path in ("/admin/upload.aspx", "/admin/upload"):
            tok, sess = self._require_auth()
            if not sess: return
            self._send(200, UPLOAD_PAGE.format(msg=""))
            return

        # ── Vulnerable endpoints (SQLi bait) ──
        q = params.get("q", [""])[0]
        uid = params.get("id", [""])[0]
        file_param = params.get("file", [""])[0]
        date_param = params.get("date", [""])[0]

        sqli_chars = ["'", '"', "--", "OR 1", "UNION", "SELECT", "DROP", "INSERT"]
        is_sqli = any(s.lower() in (q + uid + file_param).lower() for s in sqli_chars)
        if is_sqli:
            payload = q or uid or file_param
            self._log("SQLI_ATTEMPT", payload=payload)
            alerts.check_sqli(payload, self._ip())
            time.sleep(random.uniform(0.5, 1.5))  # fake query delay
            self._send(500, _sql_error(payload))
            return

        # ── Protected admin routes ──
        tok, sess = self._require_auth()
        if not sess: return
        uname = sess["username"]
        sid   = tok

        if path == "/admin/dashboard":
            self._send(200, self._dashboard(uname))
        elif path == "/admin/branches":
            self._send(200, self._branches_page(uname, q))
        elif path == "/admin/search":
            self._log("SEARCH", sid=sid, payload=q)
            self._send(200, self._branches_page(uname, q))
        elif path == "/admin/user":
            self._log("NODE_LOOKUP", sid=sid, payload=uid)
            self._send(200, self._infrastructure_page(uname, uid))
        elif path == "/admin/employees":
            self._send(200, self._employees_page(uname))
        elif path == "/admin/infrastructure":
            self._send(200, self._infrastructure_page(uname))
        elif path == "/admin/network":
            self._send(200, self._network_page(uname))
        elif path == "/admin/security":
            self._log("SOC_ACCESS", sid=sid)
            self._send(200, self._security_page(uname))
        elif path == "/admin/backups":
            self._log("BACKUP_MGMT_ACCESS", sid=sid)
            self._send(200, self._backups_page(uname))
        elif path == "/admin/documents":
            self._send(200, self._documents_page(uname))
        elif path == "/admin/settings":
            self._send(200, self._settings_page(uname))
        elif path == "/admin/database":
            self._log("DB_ACCESS", sid=sid)
            self._send(200, self._database_page(uname))
        elif path == "/admin/logs":
            self._log("LOGS_ACCESS", sid=sid, payload=date_param)
            self._send(200, self._logs_page(uname, date_param))
        elif path == "/admin/export":
            self._log("EXPORT_ATTEMPT", sid=sid, filename=file_param)
            # Return fake partial file content
            fake = f"# Laxmi Chit Fund Export: {file_param}\n# Generated: {datetime.now()}\n# CONFIDENTIAL\nid,data\n1,REDACTED\n"
            self._send(200, fake, "text/plain")
        elif path == "/admin/logout":
            _http_sessions.pop(tok, None)
            self._redirect("/admin/login.aspx")
        else:
            self._send(404, NOT_FOUND_PAGE)

    # ── POST handler ──────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        ctype  = self.headers.get("Content-Type", "")
        ip     = self._ip()

        # ── Step 1: username ──
        if path == "/admin/step1":
            body   = self.rfile.read(length).decode(errors="replace")
            params = parse_qs(body)
            username = params.get("username", [""])[0].strip()
            self._log("USERNAME_ENTERED", username=username)
            if not username:
                self._send(200, _step1_html("Please enter your username."))
            else:
                captcha = _new_captcha(ip)
                self._send(200, _step2_html(username, captcha))
            return

        # ── Step 2: password + captcha ──
        if path == "/admin/login":
            body     = self.rfile.read(length).decode(errors="replace")
            params   = parse_qs(body)
            username = params.get("username", [""])[0].strip()
            password = params.get("password", [""])[0].strip()
            captcha  = params.get("captcha",  [""])[0].strip()

            self._log("LOGIN_ATTEMPT", username=username, password=password)

            # ── Validate CAPTCHA first ──────────────────────────────────────
            expected_cap, cap_exp = _captchas.get(ip, ("", 0))
            captcha_ok = (
                captcha and
                expected_cap and
                captcha.strip().lower() == expected_cap.strip().lower() and
                time.time() < cap_exp
            )

            # ── Validate username (honeypot: only "admin" gets in) ──────────
            username_ok = (username.lower() == "admin")

            # ── Validate password ───────────────────────────────────────────
            password_ok = (password == "admin")

            if username_ok and password_ok and captcha_ok:
                # Successful login — log attacker and redirect to fake dashboard
                sid   = hp_log.new_session(ip, "HTTP")
                token = _new_http_session(username, ip)
                hp_log.log("LOGIN_SUCCESS", ip, "HTTP", sid,
                           username=username, password=password)
                # Invalidate captcha so it can't be reused
                _captchas.pop(ip, None)
                self.send_response(302)
                self.send_header("Location", "/admin/dashboard")
                self.send_header("Set-Cookie",
                    f"ASP.NET_SessionId={token}; Path=/; HttpOnly")
                self.end_headers()

            else:
                # Failed — log reason, generate fresh CAPTCHA, show error
                if not username_ok:
                    err = "Invalid Username. Access denied."
                elif not captcha_ok:
                    err = "Invalid Security Code. Please try again."
                else:
                    err = "Invalid Password. Please try again."

                self._log("LOGIN_FAILURE", username=username, password=password,
                          reason="bad_username" if not username_ok else
                                 "bad_captcha"  if not captcha_ok  else "bad_password")
                alerts.record_failed_login(ip, "HTTP", username, password)

                new_cap = _new_captcha(ip)
                self._send(401, _step2_html(username, new_cap, err))
            return

        # ── File upload trap ──
        if path in ("/admin/upload.aspx", "/admin/upload"):
            tok, sess = self._require_auth()
            if not sess: return

            filename = "unknown"
            size = length
            is_malicious = False

            # Parse multipart to get filename
            if "multipart/form-data" in ctype:
                raw = self.rfile.read(length)
                # Extract filename from Content-Disposition
                m = re.search(rb'filename="([^"]+)"', raw)
                if m:
                    filename = m.group(1).decode(errors="replace")
                    is_malicious = hp_log.detect_malicious_file(filename)

                # Save hash of malicious files
                if is_malicious:
                    h = hashlib.sha256(raw).hexdigest()
                    md5 = hashlib.md5(raw, usedforsecurity=False).hexdigest()
                    upload_path = f"uploads/{filename}_{h[:8]}.blocked"
                    try:
                        with open(upload_path, "wb") as f:
                            f.write(raw[:1024])  # save first 1KB only
                    except Exception:
                        pass
                    hp_log.log("MALICIOUS_UPLOAD", ip, "HTTP", tok,
                               filename=filename, sha256=h, md5=md5,
                               size=size)
                    alerts.check_upload(filename, ip, "HTTP", tok)
                    alerts.trigger("WEBSHELL_UPLOAD", ip, "HTTP",
                                   detail=f"Webshell: {filename} sha256={h[:16]}",
                                   filename=filename, sha256=h)
                    # Deep malware analysis
                    if _MC_OK:
                        mc.capture(raw, filename, ip, "HTTP", tok)
                else:
                    hp_log.log("FILE_UPLOAD", ip, "HTTP", tok,
                               filename=filename, size=size)
            else:
                self.rfile.read(length)

            warn = '<div class="alert err">&#9888; Malicious file detected and quarantined.</div>' \
                   if is_malicious else \
                   f'<div class="alert ok">&#10003; File "{filename}" uploaded successfully.</div>'
            self._send(200, UPLOAD_PAGE.format(msg=warn))
            return

        # Fallback
        self.rfile.read(length)
        self._send(404, "<h1>404</h1>")


# ── Server control ─────────────────────────────────────────────────────────────
_server = None
_thread = None
_cleanup_thread = None
_cleanup_stop = threading.Event()

def _sweep_expired():
    """
    Periodic housekeeping for the in-memory session/captcha stores.
    Without this, _http_sessions and _captchas grow without bound over
    a long-running process: entries are only ever removed when their
    *specific* key is revisited (logout, or a matching validate/lookup
    call) — a visitor who authenticates once and never returns leaves
    a permanent entry. Runs every 5 minutes; cheap and non-blocking.
    """
    while not _cleanup_stop.wait(300):
        try:
            now = time.time()
            expired_sessions = [t for t, s in _http_sessions.items()
                                 if now - s["last_active"] > SESSION_TIMEOUT]
            for t in expired_sessions:
                _http_sessions.pop(t, None)

            expired_captchas = [ip for ip, (_, exp) in _captchas.items() if now > exp]
            for ip in expired_captchas:
                _captchas.pop(ip, None)
        except Exception:
            pass  # housekeeping must never take the honeypot down

def start(port=8080):
    global _server, _thread, _cleanup_thread
    _server = HTTPServer(("0.0.0.0", port), HoneypotHTTPHandler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()
    _cleanup_stop.clear()
    _cleanup_thread = threading.Thread(target=_sweep_expired, daemon=True)
    _cleanup_thread.start()
    hp_log.log("HTTP_START", "0.0.0.0", "HTTP", port=port)
    print(f"[HTTP Honeypot] Listening on port {port}")

def stop():
    global _server
    _cleanup_stop.set()
    if _server:
        _server.shutdown()
        print("[HTTP Honeypot] Stopped")
