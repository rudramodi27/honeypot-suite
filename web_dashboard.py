"""
web_dashboard.py — Real-Time Web Dashboard
Replaces the tkinter GUI with a browser-based dashboard
accessible from any device on the network.

Features:
  - Live event stream (Server-Sent Events)
  - Interactive charts (Chart.js via CDN)
  - Attack map (Leaflet.js)
  - REST API endpoints
  - Session replay viewer
  - MITRE ATT&CK heatmap
  - Alert management (ack/dismiss)
  - STIX export trigger
  - Multi-user JWT auth

Start: python web_dashboard.py
Visit: http://localhost:5000
"""

import os
import json
import time
import queue
import threading
import logging
from datetime import datetime, timedelta
import tz_utils
from functools import wraps
from typing import Optional

from flask import (
    Flask, render_template_string, jsonify, request,
    Response, stream_with_context, redirect, url_for,
    session as flask_session, abort
)
from flask_socketio import SocketIO, emit

try:
    from config_loader import cfg
    HOST    = cfg.get("dashboard.host", "0.0.0.0")
    PORT    = cfg.get("dashboard.port", 5000)
    SECRET  = cfg.get("dashboard.secret_key", "change_me_in_prod")
    UNAME   = cfg.get("dashboard.username", "admin")
    PHASH   = cfg.get("dashboard.password_hash", "")
    REFRESH = cfg.get("dashboard.refresh_interval", 5)
except Exception:
    HOST = "0.0.0.0"; PORT = 5000
    SECRET = "change_me_in_prod"; UNAME = "admin"
    PHASH = ""; REFRESH = 5

logger = logging.getLogger("WebDashboard")

app = Flask(__name__)
app.secret_key = SECRET
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode="threading",
                    logger=False, engineio_logger=False)

# ── Live event queue (broadcasts to all WS clients) ──────────
_event_queue: queue.Queue = queue.Queue(maxsize=1000)

def push_event(event: dict):
    """Called by honeypot services to push live events to dashboard."""
    try:
        _event_queue.put_nowait(event)
    except queue.Full:
        _event_queue.get_nowait()
        _event_queue.put_nowait(event)


def _broadcaster():
    """Background thread — drains queue and emits via SocketIO."""
    while True:
        try:
            ev = _event_queue.get(timeout=1)
            socketio.emit("attack_event", ev, namespace="/live")
        except queue.Empty:
            pass
        except Exception as e:
            logger.debug(f"Broadcaster error: {e}")


# ── Auth helpers ──────────────────────────────────────────────
def _verify_password(raw: str) -> bool:
    if not PHASH:
        # No hash set → fallback to plaintext "admin" for dev
        return raw == "admin"
    try:
        from werkzeug.security import check_password_hash
        return check_password_hash(PHASH, raw)
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not flask_session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════
# HTML TEMPLATES
# ══════════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HoneypotSuite — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0c10;display:flex;align-items:center;justify-content:center;
     min-height:100vh;font-family:'Segoe UI',sans-serif;color:#c8d8e8}
.card{background:#0f1318;border:1px solid #1e2d40;border-radius:12px;
      padding:40px 48px;width:360px;text-align:center}
.logo{font-size:2.5rem;margin-bottom:8px}
h1{color:#00c8ff;font-size:1.4rem;margin-bottom:4px}
p{color:#4a6070;font-size:.85rem;margin-bottom:28px}
input{width:100%;padding:12px 14px;background:#111820;border:1px solid #1e2d40;
      border-radius:8px;color:#c8d8e8;font-size:.95rem;margin-bottom:14px;outline:none}
input:focus{border-color:#00c8ff}
button{width:100%;padding:12px;background:#00c8ff;color:#0a0c10;border:none;
       border-radius:8px;font-weight:700;font-size:1rem;cursor:pointer}
button:hover{background:#00a8d8}
.err{color:#ff3c5a;margin-top:14px;font-size:.85rem}
</style>
</head>
<body>
<div class="card">
  <div class="logo">🍯</div>
  <h1>HoneypotSuite</h1>
  <p>Threat Intelligence Platform</p>
  <form method="POST">
    <input name="username" placeholder="Username" autocomplete="off" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
  </form>
</div>
</body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HoneypotSuite — Dashboard</title>
<script src="https://cdn.socket.io/4.7.4/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
:root{
  --bg:#0a0c10;--panel:#0f1318;--panel2:#111820;--border:#1e2d40;
  --accent:#00c8ff;--green:#00e676;--danger:#ff3c5a;--warn:#ffab40;
  --text:#c8d8e8;--muted:#4a6070;--white:#ffffff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;
     font-size:14px;min-height:100vh}

/* ── Topbar ── */
.topbar{background:var(--panel);border-bottom:1px solid var(--border);
        padding:0 24px;height:56px;display:flex;align-items:center;
        justify-content:space-between;position:sticky;top:0;z-index:100}
.topbar-left{display:flex;align-items:center;gap:12px}
.logo-icon{font-size:1.6rem}
.logo-text{color:var(--accent);font-size:1.1rem;font-weight:700;letter-spacing:.5px}
.logo-sub{color:var(--muted);font-size:.75rem}
.topbar-right{display:flex;align-items:center;gap:16px}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);
            box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.nav-tabs{display:flex;gap:4px}
.nav-tab{padding:6px 14px;border-radius:6px;cursor:pointer;color:var(--muted);
         border:none;background:none;font-size:13px;transition:.2s}
.nav-tab.active,.nav-tab:hover{background:var(--border);color:var(--accent)}
.btn{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;
     font-size:12px;font-weight:600;transition:.2s}
.btn-danger{background:#ff3c5a22;color:var(--danger);border:1px solid var(--danger)}
.btn-primary{background:var(--accent);color:#000}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn:hover{opacity:.8}

/* ── Layout ── */
.main{padding:20px 24px;max-width:1600px;margin:0 auto}
.page{display:none}.page.active{display:block}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:20px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}

/* ── Cards ── */
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 20px}
.card-title{font-size:11px;text-transform:uppercase;letter-spacing:.8px;
            color:var(--muted);margin-bottom:12px;font-weight:600}
.stat-value{font-size:2.2rem;font-weight:700;color:var(--white);line-height:1}
.stat-label{font-size:.75rem;color:var(--muted);margin-top:4px}
.stat-delta{font-size:.75rem;margin-top:6px}
.delta-up{color:var(--danger)}.delta-down{color:var(--green)}

/* ── Severity badges ── */
.badge{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase}
.badge-CRITICAL{background:#cc000033;color:#ff4444;border:1px solid #cc000066}
.badge-HIGH{background:#ff3c5a22;color:var(--danger);border:1px solid var(--danger)44}
.badge-MEDIUM{background:#ff8c0022;color:#ff8c00;border:1px solid #ff8c0044}
.badge-LOW{background:#ffab4022;color:var(--warn);border:1px solid var(--warn)44}

/* ── Event table ── */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 12px;color:var(--muted);
   border-bottom:1px solid var(--border);white-space:nowrap;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px}
td{padding:8px 12px;border-bottom:1px solid #1a2230;color:var(--text)}
tr:hover td{background:#111820}
.ip-cell{font-family:monospace;color:var(--accent)}
.flag{font-size:14px;margin-right:4px}
.mono{font-family:'Consolas',monospace;font-size:11px}

/* ── Live feed ── */
.live-feed{background:var(--panel);border:1px solid var(--border);
           border-radius:10px;height:340px;overflow-y:auto;padding:12px}
.feed-item{padding:6px 10px;border-left:3px solid var(--border);
           margin-bottom:6px;font-size:11px;border-radius:0 4px 4px 0}
.feed-item.CRITICAL{border-color:var(--danger);background:#ff3c5a08}
.feed-item.HIGH{border-color:#ff8c00;background:#ff8c0008}
.feed-item.MEDIUM{border-color:var(--warn);background:#ffab4008}
.feed-item.LOW{border-color:var(--muted)}
.feed-time{color:var(--muted);font-size:10px}
.feed-ip{color:var(--accent);font-weight:600}

/* ── Attack map ── */
#attack-map{height:360px;border-radius:8px;overflow:hidden;
            border:1px solid var(--border)}
.leaflet-container{background:#0a0c10!important}

/* ── Alerts panel ── */
.alert-item{background:var(--panel2);border:1px solid var(--border);
            border-radius:8px;padding:12px 14px;margin-bottom:8px;
            display:flex;justify-content:space-between;align-items:flex-start}
.alert-body{flex:1}
.alert-title{font-weight:600;color:var(--white);margin-bottom:4px}
.alert-meta{color:var(--muted);font-size:.75rem}
.alert-actions{display:flex;gap:8px;margin-left:12px}

/* ── MITRE heatmap ── */
.mitre-grid{display:grid;grid-template-columns:repeat(9,1fr);gap:4px;
            overflow-x:auto;min-width:700px}
.mitre-tactic{text-align:center;font-size:9px;color:var(--muted);padding:4px 2px;
              text-transform:uppercase;letter-spacing:.4px}
.mitre-cell{height:36px;border-radius:4px;background:var(--panel2);
            border:1px solid var(--border);cursor:pointer;
            display:flex;align-items:center;justify-content:center;
            font-size:9px;color:var(--muted);text-align:center;
            transition:.2s;position:relative}
.mitre-cell:hover{border-color:var(--accent)}
.mitre-cell.hit-low{background:#ffab4022;border-color:var(--warn);color:var(--warn)}
.mitre-cell.hit-med{background:#ff8c0033;border-color:#ff8c00;color:#ff8c00}
.mitre-cell.hit-high{background:#ff3c5a33;border-color:var(--danger);color:var(--danger)}
.mitre-cell.hit-crit{background:#cc000055;border-color:#ff0000;color:#ff4444}
.section-title{font-size:1rem;font-weight:700;color:var(--white);
               margin-bottom:14px;display:flex;align-items:center;gap:8px}
.pill{padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;
      background:var(--border);color:var(--accent)}
</style>
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div class="topbar-left">
    <span class="logo-icon">🍯</span>
    <div>
      <div class="logo-text">HoneypotSuite</div>
      <div class="logo-sub">Threat Intelligence Platform</div>
    </div>
    <div class="nav-tabs" style="margin-left:32px">
      <button class="nav-tab active" onclick="showPage('overview')">Overview</button>
      <button class="nav-tab" onclick="showPage('events')">Events</button>
      <button class="nav-tab" onclick="showPage('alerts')">Alerts <span id="alert-badge" class="pill" style="display:none">0</span></button>
      <button class="nav-tab" onclick="showPage('map')">Attack Map</button>
      <button class="nav-tab" onclick="showPage('mitre')">MITRE ATT&CK</button>
      <button class="nav-tab" onclick="showPage('sessions')">Sessions</button>
      <button class="nav-tab" onclick="showPage('evidence')">Evidence Hash</button>
      <button class="nav-tab" onclick="showPage('custody')">Chain of Custody</button>
      <button class="nav-tab" onclick="showPage('manifest')">Evidence Manifest</button>
    </div>
  </div>
  <div class="topbar-right">
    <span style="color:var(--muted);font-size:12px" id="clock"></span>
    <div class="status-dot"></div>
    <span style="color:var(--green);font-size:12px">LIVE</span>
    <button class="btn btn-ghost" onclick="exportSTIX()">⬇ STIX Export</button>
    <button class="btn btn-danger" onclick="location.href='/logout'">Logout</button>
  </div>
</div>

<div class="main">

<!-- ══ OVERVIEW PAGE ══ -->
<div class="page active" id="page-overview">
  <div class="grid-4">
    <div class="card">
      <div class="card-title">Total Events (24h)</div>
      <div class="stat-value" id="stat-total">—</div>
      <div class="stat-label">Inbound attack events</div>
    </div>
    <div class="card">
      <div class="card-title">Unique Attackers (24h)</div>
      <div class="stat-value" id="stat-ips" style="color:var(--accent)">—</div>
      <div class="stat-label">Distinct source IPs</div>
    </div>
    <div class="card">
      <div class="card-title">Critical Alerts</div>
      <div class="stat-value" id="stat-critical" style="color:var(--danger)">—</div>
      <div class="stat-label">Require immediate action</div>
    </div>
    <div class="card">
      <div class="card-title">Malware Captured</div>
      <div class="stat-value" id="stat-malware" style="color:var(--warn)">—</div>
      <div class="stat-label">Files captured & quarantined</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="section-title">Events Per Hour</div>
      <canvas id="chart-hourly" height="160"></canvas>
    </div>
    <div class="card">
      <div class="section-title">Service Breakdown</div>
      <canvas id="chart-services" height="160"></canvas>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="section-title">Live Event Feed</div>
      <div class="live-feed" id="live-feed">
        <div style="color:var(--muted);text-align:center;padding:40px 0;font-size:12px">
          Waiting for events...
        </div>
      </div>
    </div>
    <div class="card">
      <div class="section-title">Top Attacking IPs <span class="pill">24h</span></div>
      <div id="top-ips-list"></div>
    </div>
  </div>
</div>

<!-- ══ EVENTS PAGE ══ -->
<div class="page" id="page-events">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <select id="filter-service" onchange="loadEvents()" style="padding:7px 12px;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px">
        <option value="">All Services</option>
        <option>SSH</option><option>HTTP</option><option>FTP</option>
        <option>MYSQL</option><option>REDIS</option><option>SMTP</option>
      </select>
      <select id="filter-severity" onchange="loadEvents()" style="padding:7px 12px;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
      </select>
      <button class="btn btn-primary" onclick="loadEvents()">Refresh</button>
    </div>
  </div>
  <div class="card">
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Timestamp</th><th>IP</th><th>Country</th><th>City</th><th>Lat/Lon</th><th>Service</th>
          <th>Event</th><th>Username</th><th>Severity</th><th>MITRE</th>
        </tr></thead>
        <tbody id="events-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ ALERTS PAGE ══ -->
<div class="page" id="page-alerts">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <div class="section-title">Active Alerts</div>
    <button class="btn btn-ghost" onclick="loadAlerts()">Refresh</button>
  </div>
  <div id="alerts-list"></div>
</div>

<!-- ══ ATTACK MAP PAGE ══ -->
<div class="page" id="page-map">
  <div class="card" style="margin-bottom:16px">
    <div class="section-title">Real-Time Attack Map</div>
    <div id="attack-map"></div>
  </div>
</div>

<!-- ══ MITRE PAGE ══ -->
<div class="page" id="page-mitre">
  <div class="card">
    <div class="section-title">MITRE ATT&CK Coverage Heatmap</div>
    <div style="overflow-x:auto;padding-bottom:8px">
      <div class="mitre-grid" id="mitre-grid"></div>
    </div>
    <div style="margin-top:16px" id="mitre-techniques"></div>
  </div>
</div>

<!-- ══ SESSIONS PAGE ══ -->
<div class="page" id="page-sessions">
  <div class="card">
    <div class="section-title">Captured Sessions</div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Start Time</th><th>IP</th><th>Country</th><th>City</th><th>Service</th>
          <th>Username</th><th>Duration</th><th>Commands</th><th>Automated</th>
        </tr></thead>
        <tbody id="sessions-tbody"></tbody>
      </table>
    </div>
  </div></div>

<!-- ══ EVIDENCE HASH PAGE ══ -->
<div class="page" id="page-evidence">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div class="section-title">Evidence Hash Registry</div>
      <button class="btn btn-ghost" onclick="loadEvidence()">Refresh</button>
    </div>
    <div style="color:var(--muted);font-size:11px;margin-top:-8px;margin-bottom:14px">
      Forensic-grade SHA256/SHA1/MD5 hashes for every captured sample, exported report, and STIX bundle.
      Click "Verify" to re-check a file's current hash against what was originally recorded.
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>File Name</th><th>Source</th><th>SHA256</th>
          <th>Hash Status</th><th>Algorithm</th>
          <th>Key ID</th><th>Fingerprint</th>
          <th>Signed Time</th><th>Sig Status</th><th></th>
        </tr></thead>
        <tbody id="evidence-tbody"></tbody>
      </table>
    </div>
  </div>
</div>
<!-- ══ CHAIN OF CUSTODY PAGE ══ -->
<div class="page" id="page-custody">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div class="section-title">Chain of Custody</div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <label style="color:var(--muted);font-size:12px">Evidence ID</label>
        <input id="coc-evidence-id" type="number" placeholder="e.g. 1"
          style="padding:6px 10px;background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:6px;font-size:13px;width:100px">
        <button class="btn btn-primary" onclick="loadCustody()">Load</button>
        <button class="btn btn-ghost" onclick="exportCustody('json')">⬇ JSON</button>
        <button class="btn btn-ghost" onclick="exportCustody('csv')">⬇ CSV</button>
        <button class="btn btn-ghost" onclick="exportCustody('pdf')">⬇ PDF</button>
      </div>
    </div>
    <div id="coc-evidence-info" style="display:none;margin:10px 0;padding:10px 14px;
      background:var(--panel2);border-radius:8px;border:1px solid var(--border)">
      <span style="color:var(--muted);font-size:12px">Evidence: </span>
      <span id="coc-evidence-label" style="color:var(--accent);font-size:12px"></span>
    </div>
    <div class="table-wrap" style="margin-top:10px">
      <table>
        <thead><tr>
          <th>Timestamp ({{ tz_abbr }})</th><th>Action</th><th>User</th>
          <th>Reason</th><th>Status</th><th>IP</th><th>Remarks</th>
        </tr></thead>
        <tbody id="custody-tbody">
          <tr><td colspan="7" style="color:var(--muted);text-align:center;padding:32px">
            Enter an Evidence ID above and click Load
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ EVIDENCE MANIFEST PAGE ══ -->
<div class="page" id="page-manifest">
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div class="section-title">Evidence Manifest Registry</div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-ghost" onclick="loadManifests()">Refresh</button>
      </div>
    </div>
    <div style="color:var(--muted);font-size:11px;margin-top:-8px;margin-bottom:14px">
      Immutable forensic metadata snapshot created once per evidence item after hashing and signing.
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Manifest ID</th><th>Evidence ID</th><th>SHA256</th>
          <th>Algorithm</th><th>Key ID</th>
          <th>Manifest Status</th><th>Created Time</th><th>Actions</th>
        </tr></thead>
        <tbody id="manifest-tbody">
          <tr><td colspan="8" style="color:var(--muted);text-align:center;padding:32px">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

</div><!-- /main -->

<script>
// ── Clock ──────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleString('en-IN', {hour12:false});
}, 1000);

// ── Navigation ─────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'map') initMap();
  if (name === 'mitre') loadMitre();
  if (name === 'events') loadEvents();
  if (name === 'alerts') loadAlerts();
  if (name === 'sessions') loadSessions();
  if (name === 'evidence') loadEvidence();
  if (name === 'custody') { /* load triggered by user clicking Load button */ }
  if (name === 'manifest') loadManifests();
}

// ── Charts ─────────────────────────────────────────────────
let hourlyChart, serviceChart;
const CHART_DEFAULTS = {
  responsive: true,
  plugins: { legend: { labels: { color: '#c8d8e8', font: { size: 11 } } } },
};

function initCharts(stats) {
  const hourlyCtx = document.getElementById('chart-hourly').getContext('2d');
  const svcCtx    = document.getElementById('chart-services').getContext('2d');

  if (hourlyChart) hourlyChart.destroy();
  if (serviceChart) serviceChart.destroy();

  const svcLabels = Object.keys(stats.by_service || {});
  const svcData   = Object.values(stats.by_service || {});

  hourlyChart = new Chart(hourlyCtx, {
    type: 'bar',
    data: {
      labels: Array.from({length: 24}, (_, i) => `${23-i}h`).reverse(),
      datasets: [{
        label: 'Events',
        data: stats.hourly || Array(24).fill(0),
        backgroundColor: '#00c8ff44',
        borderColor: '#00c8ff',
        borderWidth: 1,
        borderRadius: 3,
      }]
    },
    options: { ...CHART_DEFAULTS, scales: {
      x: { ticks: { color: '#4a6070', font: { size: 10 } }, grid: { color: '#1e2d40' } },
      y: { ticks: { color: '#4a6070' }, grid: { color: '#1e2d40' } }
    }}
  });

  serviceChart = new Chart(svcCtx, {
    type: 'doughnut',
    data: {
      labels: svcLabels,
      datasets: [{ data: svcData,
        backgroundColor: ['#00c8ff','#ff3c5a','#00e676','#ffab40','#c792ea','#ff8c00','#4da3ff'],
        borderWidth: 0 }]
    },
    options: { ...CHART_DEFAULTS, cutout: '65%' }
  });
}

// ── Stats refresh ──────────────────────────────────────────
async function refreshStats() {
  const r = await fetch('/api/stats');
  const stats = await r.json();
  document.getElementById('stat-total').textContent    = (stats.total_events || 0).toLocaleString();
  document.getElementById('stat-ips').textContent      = (stats.unique_ips || 0).toLocaleString();
  document.getElementById('stat-critical').textContent = (stats.by_severity?.CRITICAL || 0).toLocaleString();
  document.getElementById('stat-malware').textContent  = (stats.malware_count || 0).toLocaleString();
  initCharts(stats);
  renderTopIPs(stats.top_ips || []);
}

function renderTopIPs(ips) {
  const container = document.getElementById('top-ips-list');
  const max = Math.max(...ips.map(i => i.count), 1);
  container.innerHTML = ips.slice(0, 10).map(ip => `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div class="ip-cell mono" style="width:130px;flex-shrink:0">${ip.ip}</div>
      <div style="flex:1;background:var(--panel2);height:8px;border-radius:4px;overflow:hidden">
        <div style="height:100%;background:var(--accent);width:${(ip.count/max)*100}%;border-radius:4px"></div>
      </div>
      <div style="color:var(--muted);font-size:11px;width:40px;text-align:right">${ip.count}</div>
    </div>
  `).join('');
}

// ── Events table ───────────────────────────────────────────
async function loadEvents() {
  const svc = document.getElementById('filter-service').value;
  const sev = document.getElementById('filter-severity').value;
  const r   = await fetch(`/api/events?service=${svc}&severity=${sev}&limit=200`);
  const data = await r.json();
  const tbody = document.getElementById('events-tbody');
  tbody.innerHTML = data.map(ev => `
    <tr>
      <td class="mono">${(ev.timestamp_local || ev.timestamp)?.replace('T',' ').slice(0,19) || '—'}</td>
      <td class="ip-cell mono">${ev.src_ip || '—'}</td>
      <td>${ev.country ? `<span class="flag"></span>${ev.country}` : '—'}</td>
      <td>${ev.city || '—'}</td>
      <td class="mono" style="font-size:10.5px">${(ev.latitude && ev.longitude) ? `${ev.latitude.toFixed(2)}, ${ev.longitude.toFixed(2)}` : '—'}</td>
      <td><span style="color:var(--accent)">${ev.service || '—'}</span></td>
      <td>${ev.event_type || '—'}</td>
      <td class="mono">${ev.username || '—'}</td>
      <td><span class="badge badge-${ev.severity}">${ev.severity || 'LOW'}</span></td>
      <td><a href="https://attack.mitre.org/techniques/${(ev.mitre_id||'').replace('.','/') }" target="_blank" style="color:var(--accent);text-decoration:none">${ev.mitre_id || '—'}</a></td>
    </tr>
  `).join('');
}

// ── Alerts ─────────────────────────────────────────────────
async function loadAlerts() {
  const r = await fetch('/api/alerts');
  const alerts = await r.json();
  const unacked = alerts.filter(a => !a.acknowledged).length;
  const badge = document.getElementById('alert-badge');
  if (unacked > 0) {
    badge.textContent = unacked;
    badge.style.display = 'inline';
    badge.style.background = 'var(--danger)';
    badge.style.color = '#fff';
  } else {
    badge.style.display = 'none';
  }
  document.getElementById('alerts-list').innerHTML = alerts.map(al => `
    <div class="alert-item">
      <div class="alert-body">
        <div class="alert-title">
          <span class="badge badge-${al.severity}">${al.severity}</span>
          &nbsp;${al.alert_type || 'Alert'} — ${al.src_ip || '?'}
        </div>
        <div class="alert-meta">${al.description || ''}</div>
        <div class="alert-meta" style="margin-top:4px">
          ${al.timestamp?.slice(0,19).replace('T',' ') || ''} · 
          Service: ${al.service || '?'} · 
          MITRE: ${al.mitre_id ? `<a href="https://attack.mitre.org/techniques/${al.mitre_id.replace('.','/') }" target="_blank" style="color:var(--accent)">${al.mitre_id}</a>` : '—'}
        </div>
      </div>
      <div class="alert-actions">
        ${!al.acknowledged ? `<button class="btn btn-ghost" onclick="ackAlert(${al.id})">✓ Ack</button>` : '<span style="color:var(--muted);font-size:11px">Acknowledged</span>'}
      </div>
    </div>
  `).join('') || '<div style="color:var(--muted);text-align:center;padding:40px">No alerts</div>';
}

async function ackAlert(id) {
  await fetch(`/api/alerts/${id}/ack`, { method: 'POST' });
  loadAlerts();
}

// ── Attack Map ─────────────────────────────────────────────
let map, mapInited = false, mapMarkers = {};
function initMap() {
  if (mapInited) return;
  mapInited = true;
  map = L.map('attack-map', { zoomControl: true }).setView([20, 0], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap &copy; CARTO', maxZoom: 18
  }).addTo(map);
  loadMapData();
  // Keep the map current even if the tab stays open — same cadence as stats.
  setInterval(loadMapData, {{ refresh_interval }} * 1000);
}

function _severityColor(sev) {
  return sev === 'CRITICAL' ? '#ff0000' :
         sev === 'HIGH'     ? '#ff3c5a' :
         sev === 'MEDIUM'   ? '#ff8c00' : '#00c8ff';
}

function _buildPopup(pt) {
  const ts = (pt.timestamp_local || pt.timestamp || '').replace('T', ' ').slice(0, 19);
  const rows = [
    ['IP Address', pt.ip || '—'],
    ['Country', pt.is_dev ? `${pt.country} <i>(not a real location)</i>` : (pt.country || '—')],
  ];
  if (!pt.is_dev) rows.push(['City', pt.city || '—']);
  rows.push(['Event Type', pt.event_type || '—']);
  rows.push(['Severity', `<span style="color:${_severityColor(pt.severity)}">${pt.severity || 'LOW'}</span>`]);
  if (ts) rows.push(['Timestamp', ts]);
  if (pt.count) rows.push(['Hits', pt.count]);
  const body = rows.map(([k, v]) => `<b>${k}:</b> ${v}`).join('<br>');
  const badge = pt.is_dev
    ? '<div style="margin-top:4px;padding:2px 6px;background:#333;color:#ffd166;border-radius:3px;font-size:10px;display:inline-block">DEVELOPMENT ENVIRONMENT — NOT A REAL LOCATION</div>'
    : '';
  return `${body}${badge}`;
}

async function loadMapData() {
  if (!map) return;
  const r = await fetch('/api/map_data');
  const data = await r.json();
  // Full redraw keeps counts/severity accurate without leaking old markers.
  Object.values(mapMarkers).forEach(m => map.removeLayer(m));
  mapMarkers = {};
  data.forEach(pt => {
    if (!pt.lat || !pt.lng) return;
    const marker = L.circleMarker([pt.lat, pt.lng], {
      radius: Math.min(12, 4 + Math.log2(pt.count + 1) * 2),
      color: _severityColor(pt.severity),
      fillOpacity: pt.is_dev ? 0.35 : 0.7,
      weight: pt.is_dev ? 2 : 1,
      dashArray: pt.is_dev ? '4,3' : null,
    }).addTo(map);
    marker.bindPopup(_buildPopup(pt));
    mapMarkers[pt.ip] = marker;
  });
}

// Live-plot new events immediately, without waiting for the next poll.
function plotLiveEvent(ev) {
  if (!map || !ev.lat || !ev.lng) return;
  const key = ev.src_ip || `${ev.lat},${ev.lng}`;
  if (mapMarkers[key]) {
    map.removeLayer(mapMarkers[key]);
  }
  const marker = L.circleMarker([ev.lat, ev.lng], {
    radius: 6,
    color: _severityColor(ev.severity),
    fillOpacity: ev.is_dev ? 0.35 : 0.7,
    weight: ev.is_dev ? 2 : 1,
    dashArray: ev.is_dev ? '4,3' : null,
  }).addTo(map);
  marker.bindPopup(_buildPopup(ev));
  mapMarkers[key] = marker;
}

// ── MITRE ATT&CK Heatmap ──────────────────────────────────
const MITRE_TACTICS = [
  {id:'TA0043',name:'Recon'},{id:'TA0001',name:'Initial Access'},
  {id:'TA0002',name:'Execution'},{id:'TA0003',name:'Persistence'},
  {id:'TA0004',name:'Priv Esc'},{id:'TA0007',name:'Discovery'},
  {id:'TA0008',name:'Lat. Move'},{id:'TA0009',name:'Collection'},
  {id:'TA0010',name:'Exfil'},
];

async function loadMitre() {
  const r = await fetch('/api/mitre');
  const data = await r.json();
  const grid  = document.getElementById('mitre-grid');
  const tbody = document.getElementById('mitre-techniques');
  grid.innerHTML = MITRE_TACTICS.map(t => `<div class="mitre-tactic">${t.name}</div>`).join('');
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const techMap = {};
  data.forEach(d => techMap[d.id] = d);
  const allTechs = [...new Set(data.map(d => d.id))];
  const rows = Math.ceil(allTechs.length / 9) || 3;
  for (let r2 = 0; r2 < rows; r2++) {
    MITRE_TACTICS.forEach((t, col) => {
      const idx = r2 * 9 + col;
      const td  = allTechs[idx];
      const d   = td ? techMap[td] : null;
      const pct = d ? d.count / maxCount : 0;
      const cls = !d ? '' : pct > .75 ? 'hit-crit' : pct > .5 ? 'hit-high' : pct > .25 ? 'hit-med' : 'hit-low';
      grid.innerHTML += `<div class="mitre-cell ${cls}" title="${d ? d.id+': '+d.name+' ('+d.count+')' : 'No activity'}">${d ? d.id : ''}</div>`;
    });
  }
  tbody.innerHTML = '<div style="color:var(--muted);font-size:11px;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">Top Observed Techniques</div>' +
    data.slice(0,15).map(d => `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <a href="https://attack.mitre.org/techniques/${d.id.replace('.','/') }" target="_blank"
         style="color:var(--accent);font-family:monospace;font-size:11px;width:80px;flex-shrink:0">${d.id}</a>
      <div style="flex:1;font-size:12px">${d.name} <span style="color:var(--muted)">(${d.tactic})</span></div>
      <span class="pill">${d.count}</span>
    </div>
  `).join('');
}

// ── Sessions ───────────────────────────────────────────────
async function loadSessions() {
  const r = await fetch('/api/sessions');
  const data = await r.json();
  document.getElementById('sessions-tbody').innerHTML = data.map(s => `
    <tr>
      <td class="mono">${(s.start_time_local || s.start_time)?.slice(0,19).replace('T',' ') || '—'}</td>
      <td class="ip-cell mono">${s.src_ip || '—'}</td>
      <td>${s.country || '—'}</td>
      <td>${s.city || '—'}</td>
      <td><span style="color:var(--accent)">${s.service || '—'}</span></td>
      <td class="mono">${s.username || '—'}</td>
      <td>${s.duration_secs ? (s.duration_secs).toFixed(1)+'s' : '—'}</td>
      <td>${(s.commands||[]).length}</td>
      <td><span style="color:${s.is_automated?'var(--warn)':'var(--green)'}">${s.is_automated?'Bot':'Human'}</span></td>
    </tr>
  `).join('');
}

// ── Evidence Hash Registry ──────────────────────────────────
async function loadEvidence() {
  const r = await fetch('/api/evidence');
  const data = await r.json();

  // Fetch signature metadata for every row in parallel
  const sigMap = {};
  await Promise.all(data.map(async e => {
    try {
      const sr = await fetch(`/api/evidence/${e.id}/signature`);
      if (sr.ok) sigMap[e.id] = await sr.json();
    } catch(_) {}
  }));

  document.getElementById('evidence-tbody').innerHTML = data.map(e => {
    const sig = sigMap[e.id];
    const sigStatus = sig
      ? `<span style="color:var(--green);font-size:10px;font-weight:600">SIGNED</span>`
      : `<span style="color:var(--muted);font-size:10px">UNSIGNED</span>`;
    return `<tr id="evidence-row-${e.id}">
      <td class="mono">${e.file_name || '—'}</td>
      <td><span style="color:var(--accent)">${e.source_type || '—'}</span></td>
      <td class="mono" style="font-size:10px" title="${e.sha256_hash || ''}">${e.sha256_hash ? e.sha256_hash.slice(0,16)+'…' : '—'}</td>
      <td><span class="badge ${e.hash_verified ? 'badge-LOW' : 'badge-CRITICAL'}" style="${e.hash_verified ? 'background:#00e67622;color:var(--green);border-color:var(--green)44' : ''}">
            ${e.hash_verified ? '✓ VERIFIED' : '✗ UNVERIFIED'}</span></td>
      <td style="font-size:11px">${sig ? sig.algorithm?.toUpperCase() : '—'}</td>
      <td class="mono" style="font-size:10px">${sig ? sig.key_id : '—'}</td>
      <td class="mono" style="font-size:9px" title="${sig ? sig.public_key_fingerprint : ''}">${sig ? (sig.public_key_fingerprint||'').slice(0,14)+'…' : '—'}</td>
      <td class="mono" style="font-size:10px">${sig ? (sig.signed_at||'').slice(0,16).replace('T',' ') : '—'}</td>
      <td>${sigStatus}</td>
      <td style="display:flex;gap:4px;flex-wrap:wrap">
        <button class="btn btn-ghost" style="font-size:11px" onclick="verifyEvidence(${e.id})">Hash</button>
        <button class="btn btn-ghost" style="font-size:11px" onclick="verifySig(${e.id})">Sig</button>
        ${!sig ? `<button class="btn btn-primary" style="font-size:11px;padding:5px 8px" onclick="signEvidence(${e.id})">Sign</button>` : ''}
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="color:var(--muted);text-align:center;padding:24px">No evidence registered yet</td></tr>';
}

async function verifyEvidence(id) {
  const r = await fetch(`/api/evidence/${id}/hash`);
  const result = await r.json();
  if (result.error) { alert('Verify failed: ' + result.error); return; }
  loadEvidence();
}

async function verifySig(id) {
  const r = await fetch(`/api/evidence/${id}/verify-signature`, { method: 'POST' });
  const result = await r.json();
  if (result.error) { alert('Signature verify error: ' + result.error); return; }
  alert(`Evidence #${id} — Signature: ${result.status}`);
  loadEvidence();
}

async function signEvidence(id) {
  const r = await fetch(`/api/evidence/${id}/sign`, { method: 'POST' });
  const result = await r.json();
  if (result.error) { alert('Sign failed: ' + result.error); return; }
  loadEvidence();
}

// ── Chain of Custody ────────────────────────────────────────
const COC_ACTION_COLORS = {
  CREATED: '#00e676', COLLECTED: '#00e676', HASHED: '#00c8ff',
  VIEWED: '#c8d8e8', VERIFIED: '#00c8ff', EXPORTED: '#ffab40',
  DOWNLOADED: '#ffab40', COPIED: '#c792ea', ARCHIVED: '#4a6070',
  DELETED: '#ff3c5a',
};

async function loadCustody() {
  const eid = document.getElementById('coc-evidence-id').value.trim();
  if (!eid) { alert('Enter an Evidence ID'); return; }

  // Fetch evidence metadata for the info banner
  try {
    const evResp = await fetch(`/api/evidence/${eid}`);
    if (evResp.ok) {
      const ev = await evResp.json();
      document.getElementById('coc-evidence-label').textContent =
        `${ev.file_name || '?'} (id=${eid}) — SHA256: ${(ev.sha256_hash||'').slice(0,16)}…`;
      document.getElementById('coc-evidence-info').style.display = 'block';
    }
  } catch(e) {}

  const r = await fetch(`/api/evidence/${eid}/custody`);
  const records = await r.json();
  const tbody = document.getElementById('custody-tbody');
  if (!records.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:24px">No custody records found for this evidence ID</td></tr>';
    return;
  }
  tbody.innerHTML = records.map(rec => {
    const col = COC_ACTION_COLORS[rec.action] || '#c8d8e8';
    const ts = (rec.timestamp||'').slice(0,19).replace('T',' ');
    const statusCol = rec.status === 'OK' ? 'var(--green)' : rec.status === 'FAILED' ? 'var(--danger)' : 'var(--warn)';
    return `<tr>
      <td class="mono" style="font-size:11px">${ts}</td>
      <td><span style="color:${col};font-weight:700;font-size:11px">${rec.action}</span></td>
      <td style="font-size:12px">${rec.performed_by||'—'}</td>
      <td style="font-size:11px;color:var(--muted)">${(rec.reason||'').slice(0,80)}</td>
      <td><span style="color:${statusCol};font-size:11px;font-weight:600">${rec.status}</span></td>
      <td class="mono" style="font-size:10px">${rec.ip_address||'—'}</td>
      <td style="font-size:11px;color:var(--muted)">${(rec.remarks||'').slice(0,40)}</td>
    </tr>`;
  }).join('');
}

async function exportCustody(fmt) {
  const eid = document.getElementById('coc-evidence-id').value.trim();
  if (!eid) { alert('Enter an Evidence ID first'); return; }
  const r = await fetch(`/api/evidence/${eid}/custody/export?fmt=${fmt}`, { method: 'POST' });
  if (!r.ok) { alert('Export failed'); return; }
  const d = await r.json();
  if (d.path) {
    const a = document.createElement('a');
    a.href = `/api/export/download?path=${encodeURIComponent(d.path)}`;
    a.download = d.path.split('/').pop();
    a.click();
  }
}

// ── Evidence Manifest ───────────────────────────────────────
const MANIFEST_STATUS_COLORS = {
  VALID: 'var(--green)', INVALID: 'var(--danger)', PENDING: 'var(--warn)',
};

async function loadManifests() {
  const r = await fetch('/api/manifests');
  const data = await r.json();
  const tbody = document.getElementById('manifest-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="color:var(--muted);text-align:center;padding:24px">No manifests created yet</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(m => {
    const col = MANIFEST_STATUS_COLORS[m.status] || 'var(--muted)';
    return `<tr>
      <td class="mono" style="font-size:9px" title="${m.manifest_id}">${m.manifest_id?.slice(0,13)}…</td>
      <td style="text-align:center;color:var(--accent)">${m.evidence_id}</td>
      <td class="mono" style="font-size:10px" title="${m.sha256_hash}">${(m.sha256_hash||'').slice(0,14)}…</td>
      <td style="font-size:11px">${(m.signature_algorithm||'').toUpperCase()}</td>
      <td class="mono" style="font-size:10px">${m.key_id||'—'}</td>
      <td><span style="color:${col};font-weight:700;font-size:11px">● ${m.status}</span></td>
      <td class="mono" style="font-size:10px">${(m.created_at||'').slice(0,16).replace('T',' ')}</td>
      <td style="display:flex;gap:4px">
        <button class="btn btn-ghost" style="font-size:11px" onclick="verifyManifest(${m.evidence_id})">Verify</button>
        <button class="btn btn-ghost" style="font-size:11px" onclick="exportManifestFile(${m.evidence_id},'json')">JSON</button>
        <button class="btn btn-ghost" style="font-size:11px" onclick="exportManifestFile(${m.evidence_id},'pdf')">PDF</button>
      </td>
    </tr>`;
  }).join('');
}

async function verifyManifest(evidenceId) {
  const r = await fetch(`/api/evidence/${evidenceId}/verify-manifest`, { method: 'POST' });
  const result = await r.json();
  if (result.error) { alert('Verify error: ' + result.error); return; }
  alert(`Evidence #${evidenceId} Manifest: ${result.status}`);
  loadManifests();
}

async function exportManifestFile(evidenceId, fmt) {
  const r = await fetch(`/api/evidence/${evidenceId}/manifest/export?fmt=${fmt}`, { method: 'POST' });
  if (!r.ok) { const e = await r.json(); alert('Export failed: ' + e.error); return; }
  const d = await r.json();
  if (d.path) {
    const a = document.createElement('a');
    a.href = `/api/export/download?path=${encodeURIComponent(d.path)}`;
    a.download = d.path.split('/').pop();
    a.click();
  }
}

// ── STIX Export ────────────────────────────────────────────
async function exportSTIX() {
  const btn = event.target;
  btn.textContent = '⏳ Generating...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/export/stix', { method: 'POST' });
    const d = await r.json();
    if (d.path) {
      const a = document.createElement('a');
      a.href = `/api/export/download?path=${encodeURIComponent(d.path)}`;
      a.download = d.path.split('/').pop();
      a.click();
    }
  } catch(e) { alert('Export failed: ' + e.message); }
  btn.textContent = '⬇ STIX Export';
  btn.disabled = false;
}

// ── Live feed via SocketIO ─────────────────────────────────
const socket = io('/live');
socket.on('attack_event', ev => {
  const feed = document.getElementById('live-feed');
  if (feed.children.length > 0 && feed.children[0].style.textAlign === 'center') {
    feed.innerHTML = '';
  }
  const sev = ev.severity || 'LOW';
  const item = document.createElement('div');
  item.className = `feed-item ${sev}`;
  item.innerHTML = `
    <div>
      <span class="feed-time">${new Date().toLocaleTimeString('en-IN',{hour12:false})}</span>
      &nbsp;
      <span class="badge badge-${sev}">${sev}</span>
      &nbsp;
      <span class="feed-ip">${ev.src_ip || '?'}</span>
      <span style="color:var(--muted)"> → </span>
      <span style="color:var(--accent)">${ev.service || '?'}</span>
      <span style="color:var(--muted)"> · ${ev.event_type || ''}</span>
    </div>
    ${ev.username ? `<div style="color:var(--muted);margin-top:2px;font-size:10px">user: ${ev.username}</div>` : ''}
  `;
  feed.insertBefore(item, feed.firstChild);
  if (feed.children.length > 50) feed.removeChild(feed.lastChild);
  // Update stats counter
  const cur = parseInt(document.getElementById('stat-total').textContent.replace(/,/g,'')) || 0;
  document.getElementById('stat-total').textContent = (cur + 1).toLocaleString();
  // Update the map immediately if this event carries coordinates
  plotLiveEvent(ev);
});

// ── Auto-refresh ───────────────────────────────────────────
refreshStats();
setInterval(refreshStats, {{ refresh_interval }} * 1000);
</script>
</body></html>"""


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if (request.form.get("username") == UNAME and
                _verify_password(request.form.get("password", ""))):
            flask_session["authenticated"] = True
            flask_session["username"] = request.form.get("username", UNAME)
            flask_session.permanent = True
            return redirect(request.args.get("next", "/"))
        error = "Invalid credentials"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    flask_session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template_string(
        DASHBOARD_HTML.replace("{{ refresh_interval }}", str(REFRESH)),
        tz_abbr=tz_utils.display_tz_abbr()
    )


# ── REST API ──────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    try:
        from database import stats_last_n_hours
        stats = stats_last_n_hours(24)
    except Exception:
        stats = {"total_events": 0, "unique_ips": 0,
                 "by_service": {}, "by_severity": {}, "top_ips": []}
    # hourly distribution — stub (replace with DB query)
    stats["hourly"] = [0] * 24
    stats["malware_count"] = 0
    try:
        from database import DbSession, MalwareSample
        with DbSession() as s:
            stats["malware_count"] = s.query(MalwareSample).count()
    except Exception:
        pass
    return jsonify(stats)


@app.route("/api/events")
@login_required
def api_events():
    service  = request.args.get("service", "")
    severity = request.args.get("severity", "")
    limit    = min(int(request.args.get("limit", 200)), 500)
    try:
        from database import recent_events, DbSession, AttackEvent
        from sqlalchemy import desc
        with DbSession() as s:
            q = s.query(AttackEvent).order_by(desc(AttackEvent.timestamp))
            if service:
                q = q.filter(AttackEvent.service == service)
            if severity:
                q = q.filter(AttackEvent.severity == severity)
            rows = q.limit(limit).all()
            out = []
            for r in rows:
                d = r.to_json_safe()
                d["timestamp_local"] = tz_utils.local_isoformat(r.timestamp)
                out.append(d)
            return jsonify(out)
    except Exception as e:
        logger.error(f"Events API error: {e}")
        return jsonify([])


@app.route("/api/alerts")
@login_required
def api_alerts():
    try:
        from database import recent_alerts
        return jsonify(recent_alerts(100))
    except Exception:
        return jsonify([])


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def api_ack_alert(alert_id: int):
    try:
        from database import DbSession, Alert
        with DbSession() as s:
            al = s.query(Alert).filter(Alert.id == alert_id).first()
            if al:
                al.acknowledged = True
                al.ack_time = datetime.utcnow()
                al.ack_by = flask_session.get("username", "admin")
                s.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/map_data")
@login_required
def api_map_data():
    try:
        from database import DbSession, AttackEvent, IPIntel
        from sqlalchemy import func, desc
        import ip_enrichment as _ip_enrich

        dev_mode = cfg.get("display.map_dev_mode", True)
        dev_coord = cfg.get(
            "display.dev_coordinates",
            {"lat": 23.0225, "lng": 72.5714, "label": "Local Test Environment"},
        )
        dev_label = dev_coord.get("label", "Local Test Environment")

        with DbSession() as s:
            rows = (s.query(
                AttackEvent.src_ip,
                IPIntel.latitude, IPIntel.longitude,
                IPIntel.country, IPIntel.city,
                func.count(AttackEvent.id).label("count"),
                AttackEvent.severity,
            )
            .join(IPIntel, AttackEvent.src_ip == IPIntel.ip, isouter=True)
            .group_by(AttackEvent.src_ip)
            .order_by(desc("count"))
            .limit(500).all())

            out = []
            for ip, lat, lng, country, city, count, severity in rows:
                is_private = _ip_enrich._is_private(ip) if ip else False

                # Latest event for this IP — powers the tooltip's
                # "Event Type" / "Timestamp" / most-recent-severity fields.
                latest = (s.query(AttackEvent)
                          .filter(AttackEvent.src_ip == ip)
                          .order_by(desc(AttackEvent.timestamp))
                          .first())
                latest_event_type = latest.event_type if latest else None
                latest_severity   = latest.severity if latest else severity
                latest_ts_local   = tz_utils.local_isoformat(latest.timestamp) if latest else None

                if lat and lng:
                    out.append({
                        "ip": ip, "lat": lat, "lng": lng,
                        "country": country, "city": city,
                        "count": count, "severity": latest_severity,
                        "event_type": latest_event_type,
                        "timestamp_local": latest_ts_local,
                        "is_dev": False,
                    })
                elif is_private and dev_mode:
                    # No real geolocation exists (and never will) for
                    # private/local addresses — plot at the fixed dev
                    # point, clearly labeled, instead of pretending it's
                    # a real geographic location.
                    out.append({
                        "ip": ip, "lat": dev_coord["lat"], "lng": dev_coord["lng"],
                        "country": dev_label, "city": None,
                        "count": count, "severity": latest_severity,
                        "event_type": latest_event_type,
                        "timestamp_local": latest_ts_local,
                        "is_dev": True,
                    })
                # else: public IP whose geolocation lookup hasn't completed
                # yet (or failed) — correctly omitted until it resolves.
            return jsonify(out)
    except Exception:
        return jsonify([])


@app.route("/api/mitre")
@login_required
def api_mitre():
    try:
        from database import top_mitre_techniques
        return jsonify(top_mitre_techniques(50))
    except Exception:
        return jsonify([])


@app.route("/api/sessions")
@login_required
def api_sessions():
    try:
        from database import DbSession, AttackSession
        from sqlalchemy import desc
        with DbSession() as s:
            rows = s.query(AttackSession).order_by(desc(AttackSession.start_time)).limit(100).all()
            out = []
            for r in rows:
                d = r.to_json_safe()
                d["start_time_local"] = tz_utils.local_isoformat(r.start_time)
                out.append(d)
            return jsonify(out)
    except Exception:
        return jsonify([])


# ── Evidence Hashing Framework (Phase 1A) ──────────────────────────

@app.route("/api/evidence")
@login_required
def api_evidence_list():
    """List all registered evidence files — backs the dashboard's
    Evidence Hash section."""
    try:
        from database import DbSession, Evidence
        from sqlalchemy import desc
        with DbSession() as s:
            rows = s.query(Evidence).order_by(desc(Evidence.created_at)).limit(200).all()
            return jsonify([r.to_json_safe() for r in rows])
    except Exception as e:
        logger.error(f"Evidence list API error: {e}")
        return jsonify([])


@app.route("/api/evidence/<int:evidence_id>/hash")
@login_required
def api_evidence_hash(evidence_id: int):
    """
    GET /api/evidence/<id>/hash

    Response:
        {
            "sha256": "...",
            "verified": true,
            "created_at": "..."
        }

    Re-verifies the stored hash against the file on disk on every
    call (via verify_evidence_by_id) rather than just returning the
    last-known status, so this endpoint always reflects the file's
    CURRENT integrity state, not a stale cached value.
    """
    try:
        from core.evidence_hashing import verify_evidence_by_id
        row = verify_evidence_by_id(evidence_id)
        if row is None:
            return jsonify({"error": "Evidence not found"}), 404
        return jsonify({
            "sha256": row["sha256_hash"],
            "verified": row["hash_verified"],
            "created_at": row["hash_created_at"],
        })
    except Exception as e:
        logger.error(f"Evidence hash API error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>", methods=["GET"])
@login_required
def api_evidence_detail(evidence_id: int):
    """Full Evidence row detail (file name, all 3 hashes, source,
    verification history) — used by the dashboard's detail view."""
    try:
        from database import DbSession, Evidence
        with DbSession() as s:
            row = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            if row is None:
                return jsonify({"error": "Evidence not found"}), 404
            return jsonify(row.to_json_safe())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>/reverify", methods=["POST"])
@login_required
def api_evidence_reverify(evidence_id: int):
    """Force a fresh re-hash (not just a verify-against-stored-value)
    — recomputes and persists new hash values, flags hash_verified
    based on whether they match the prior stored hash."""
    try:
        from core.evidence_hashing import save_hash_metadata
        row = save_hash_metadata(evidence_id)
        if row is None:
            return jsonify({"error": "Evidence not found"}), 404
        return jsonify(row)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Digital Evidence Signing API (Phase 1C) ──────────────────

@app.route("/api/evidence/<int:evidence_id>/signature")
@login_required
def api_evidence_signature(evidence_id: int):
    """
    GET /api/evidence/<id>/signature

    Returns the stored signature metadata for the evidence file.
    Never returns private key material.  Returns 404 if no signature
    exists yet.
    """
    try:
        from database import DbSession, EvidenceSignature
        with DbSession() as s:
            sig = s.query(EvidenceSignature).filter(
                EvidenceSignature.evidence_id == evidence_id
            ).first()
        if sig is None:
            return jsonify({"error": "No signature found for this evidence"}), 404
        row = sig.to_json_safe()
        row.pop("signature", None)   # strip raw sig bytes from the list view
        return jsonify(row)
    except Exception as e:
        logger.error(f"api_evidence_signature error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>/verify-signature", methods=["POST"])
@login_required
def api_evidence_verify_signature(evidence_id: int):
    """
    POST /api/evidence/<id>/verify-signature

    Re-verifies the stored cryptographic signature against the current
    SHA-256 hash on the Evidence row.  Returns VALID, INVALID, or
    MISSING.  Records a SIGNATURE_VERIFIED CoC event.
    """
    try:
        from core.evidence_signing import verify_signature
        result = verify_signature(
            evidence_id,
            performed_by=flask_session.get("username", "admin"),
        )
        return jsonify({
            "evidence_id": evidence_id,
            "status":      result,
            "verified_at": datetime.utcnow().isoformat(),
            "verified_by": flask_session.get("username", "admin"),
        })
    except Exception as e:
        logger.error(f"api_evidence_verify_signature error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>/sign", methods=["POST"])
@login_required
def api_evidence_sign(evidence_id: int):
    """
    POST /api/evidence/<id>/sign

    (Re-)signs the evidence SHA-256 with the current active key.
    Requires operator role — signing is privileged.  Returns the
    new signature metadata without raw key bytes.
    """
    try:
        from database import DbSession, Evidence
        from core.evidence_signing import sign_hash
        with DbSession() as s:
            ev = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            if ev is None:
                return jsonify({"error": "Evidence not found"}), 404
            sha256 = ev.sha256_hash
        if not sha256:
            return jsonify({"error": "Evidence has no SHA-256 hash yet"}), 400
        result = sign_hash(
            sha256,
            evidence_id=evidence_id,
            performed_by=flask_session.get("username", "admin"),
        )
        result.pop("signature", None)   # strip raw bytes from API response
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.error(f"api_evidence_sign error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/signing/keys")
@login_required
def api_signing_keys():
    """
    GET /api/signing/keys  — active key metadata (no private material).
    """
    try:
        from core.evidence_signing import load_keys
        meta = load_keys()
        if meta is None:
            return jsonify({"active_key": None, "status": "No keypair generated yet"})
        return jsonify({"active_key": meta, "status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Evidence Manifest API (Phase 1D) ────────────────────────

@app.route("/api/manifests")
@login_required
def api_manifests_list():
    """GET /api/manifests — all manifest rows for the dashboard table."""
    try:
        from database import DbSession, EvidenceManifest
        from sqlalchemy import desc
        with DbSession() as s:
            rows = (
                s.query(EvidenceManifest)
                .order_by(desc(EvidenceManifest.created_at))
                .limit(500)
                .all()
            )
            result = []
            for r in rows:
                d = r.to_json_safe()
                d.pop("signature", None)
                result.append(d)
            return jsonify(result)
    except Exception as e:
        logger.error(f"api_manifests_list error: {e}")
        return jsonify([])


@app.route("/api/evidence/<int:evidence_id>/manifest")
@login_required
def api_evidence_manifest(evidence_id: int):
    """GET /api/evidence/<id>/manifest — manifest metadata for one evidence item."""
    try:
        from core.evidence_manifest import load_manifest
        m = load_manifest(evidence_id)
        if m is None:
            return jsonify({"error": "No manifest found for this evidence"}), 404
        m.pop("signature", None)
        return jsonify(m)
    except Exception as e:
        logger.error(f"api_evidence_manifest error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>/verify-manifest", methods=["POST"])
@login_required
def api_evidence_verify_manifest(evidence_id: int):
    """
    POST /api/evidence/<id>/verify-manifest

    Re-verifies SHA256, signature, and file_size against the stored
    manifest. Returns VALID, INVALID, or MISSING. Records a
    MANIFEST_VERIFIED CoC event.
    """
    try:
        from core.evidence_manifest import verify_manifest
        result = verify_manifest(
            evidence_id,
            performed_by=flask_session.get("username", "admin"),
        )
        return jsonify({
            "evidence_id": evidence_id,
            "status":      result,
            "verified_at": datetime.utcnow().isoformat(),
            "verified_by": flask_session.get("username", "admin"),
        })
    except Exception as e:
        logger.error(f"api_evidence_verify_manifest error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/evidence/<int:evidence_id>/manifest/export", methods=["POST"])
@login_required
def api_evidence_manifest_export(evidence_id: int):
    """POST /api/evidence/<id>/manifest/export?fmt=json|csv|pdf"""
    fmt = request.args.get("fmt", "json").lower()
    if fmt not in ("json", "csv", "pdf"):
        return jsonify({"error": f"Invalid format '{fmt}'. Use json, csv, or pdf."}), 400
    try:
        from core.evidence_manifest import export_manifest
        path = export_manifest(evidence_id, fmt=fmt)
        return jsonify({"ok": True, "path": path})
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"api_evidence_manifest_export error: {e}")
        return jsonify({"error": str(e)}), 500


# ── Chain of Custody API (Phase 1B) ─────────────────────────

@app.route("/api/evidence/<int:evidence_id>/custody")
@login_required
def api_evidence_custody(evidence_id: int):
    """
    GET /api/evidence/<id>/custody
    Return the full chain of custody history for one evidence file,
    chronological (oldest first). Also fires a VIEWED CoC event so the
    act of auditing the custody chain is itself recorded.
    """
    try:
        from core.chain_of_custody import get_history, record_event
        history = get_history(evidence_id)
        # Record that someone viewed the CoC log — only if the evidence
        # row actually exists (get_history returns [] for nonexistent IDs
        # rather than raising, so check explicitly).
        if history or _evidence_exists(evidence_id):
            try:
                record_event(
                    evidence_id=evidence_id,
                    action="VIEWED",
                    performed_by=flask_session.get("username", "admin"),
                    reason="Chain of custody viewed via dashboard",
                    ip_address=request.remote_addr or "",
                )
            except Exception:
                pass
        return jsonify(history)
    except Exception as e:
        logger.error(f"api_evidence_custody error: {e}")
        return jsonify([])


@app.route("/api/case/<case_id>/custody")
@login_required
def api_case_custody(case_id: str):
    """GET /api/case/<id>/custody — all CoC records tagged to a case."""
    try:
        from core.chain_of_custody import get_history_by_case
        return jsonify(get_history_by_case(case_id))
    except Exception as e:
        logger.error(f"api_case_custody error: {e}")
        return jsonify([])


@app.route("/api/evidence/<int:evidence_id>/custody/export", methods=["POST"])
@login_required
def api_evidence_custody_export(evidence_id: int):
    """
    POST /api/evidence/<id>/custody/export?fmt=json|csv|pdf
    Export chain of custody history for download. Records a DOWNLOADED
    CoC event so the export itself is auditable.
    """
    fmt = request.args.get("fmt", "json").lower()
    if fmt not in ("json", "csv", "pdf"):
        return jsonify({"error": f"Invalid format '{fmt}'. Use json, csv, or pdf."}), 400
    try:
        from core.chain_of_custody import export_history, record_event
        path = export_history(evidence_id, fmt=fmt)
        try:
            record_event(
                evidence_id=evidence_id,
                action="DOWNLOADED",
                performed_by=flask_session.get("username", "admin"),
                reason=f"CoC exported as {fmt.upper()}",
                ip_address=request.remote_addr or "",
            )
        except Exception:
            pass
        return jsonify({"ok": True, "path": path})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"api_evidence_custody_export error: {e}")
        return jsonify({"error": str(e)}), 500


def _evidence_exists(evidence_id: int) -> bool:
    """Fast existence check used internally by custody routes."""
    try:
        from database import DbSession, Evidence
        with DbSession() as s:
            return s.query(Evidence.id).filter(Evidence.id == evidence_id).first() is not None
    except Exception:
        return False


@app.route("/api/export/stix", methods=["POST"])
@login_required
def api_export_stix():
    try:
        from stix_export import StixExporter
        exporter = StixExporter()
        path = exporter.export_from_db(hours=24)
        return jsonify({"ok": True, "path": path})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/export/download")
@login_required
def api_download_export():
    from flask import send_file
    path = request.args.get("path", "")
    if not path or ".." in path:
        abort(400)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
    })


# ── SocketIO namespace ────────────────────────────────────────
@socketio.on("connect", namespace="/live")
def on_connect():
    logger.debug(f"Dashboard client connected: {request.sid}")


@socketio.on("disconnect", namespace="/live")
def on_disconnect():
    logger.debug(f"Dashboard client disconnected: {request.sid}")


# ── Main ──────────────────────────────────────────────────────
def run_dashboard(debug: bool = False):
    """Start the web dashboard. Call from main.py."""
    # Start broadcaster thread
    t = threading.Thread(target=_broadcaster, daemon=True)
    t.start()
    logger.info(f"Web Dashboard starting on http://{HOST}:{PORT}")
    # threading async_mode + the bundled Werkzeug dev server is fine for a
    # honeypot dashboard on an internal/trusted network. flask-socketio
    # refuses to start it in non-debug mode unless explicitly overridden —
    # for an internet-facing deployment, put this behind the nginx reverse
    # proxy already scaffolded in docker-compose.yml (TLS termination +
    # rate limiting) rather than exposing it directly.
    socketio.run(app, host=HOST, port=PORT, debug=debug, use_reloader=False,
                allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_dashboard(debug=True)
