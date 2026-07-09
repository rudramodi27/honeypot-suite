"""
analytics_dashboard.py — Interactive Analytics Dashboard
Opens a full-screen dashboard window with live charts:

1. Attacks Per Hour     — bar chart (last 24h)
2. Service Breakdown    — pie chart
3. Top Countries        — horizontal bar chart
4. Command Frequency    — bar chart (SSH commands)
5. Alert Severity       — donut chart
6. Attack Timeline      — line chart (last 7 days)

Pure tkinter + Canvas — no matplotlib needed.
Auto-refreshes every 10 seconds.
"""

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk=None; ttk=None
import json, os, math, time
from datetime import datetime, timedelta
from collections import defaultdict

MASTER_LOG  = "logs/honeypot_master.log"
ALERT_LOG   = "alerts/alerts.log"

# ── Color palette ─────────────────────────────────────────────────────────────
C = {
    "bg":      "#0a0c10",
    "panel":   "#0f1318",
    "panel2":  "#111820",
    "border":  "#1e2d40",
    "accent":  "#00c8ff",
    "green":   "#00e676",
    "danger":  "#ff3c5a",
    "warn":    "#ffab40",
    "purple":  "#c792ea",
    "orange":  "#ff8c00",
    "text":    "#c8d8e8",
    "muted":   "#4a6070",
    "white":   "#ffffff",
}

CHART_COLORS = [
    "#00c8ff", "#ff3c5a", "#00e676", "#ffab40",
    "#c792ea", "#ff8c00", "#4da3ff", "#39ff14",
    "#f0a500", "#7fdbff", "#ff6b6b", "#51cf66",
]

SEV_COLORS = {
    "CRITICAL": "#cc0000",
    "HIGH":     "#ff3c5a",
    "MEDIUM":   "#ff8c00",
    "LOW":      "#ffab40",
}

SVC_COLORS = {
    "HTTP":  "#00c8ff",
    "FTP":   "#ffab40",
    "SSH":   "#c792ea",
    "MYSQL": "#ff8c00",
    "REDIS": "#ff4136",
    "SMTP":  "#7fdbff",
    "DNS":   "#39ff14",
    "ES":    "#f0a500",
}

MONO  = ("Consolas", 9)
MONO2 = ("Consolas", 10)
SUI   = ("Segoe UI", 9)
SUI_B = ("Segoe UI", 9, "bold")
SUI_H = ("Segoe UI", 11, "bold")
SUI_T = ("Segoe UI", 13, "bold")


# ── Data loading ──────────────────────────────────────────────────────────────
def _load_events(hours: int = 168) -> list[dict]:  # 168h = 7 days
    cutoff = datetime.now() - timedelta(hours=hours)
    events = []
    try:
        with open(MASTER_LOG, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    e = json.loads(line)
                    ts = datetime.fromisoformat(e.get("timestamp","")[:19])
                    if ts >= cutoff:
                        events.append(e)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return events


def _load_alerts() -> list[dict]:
    alerts = []
    cutoff = datetime.now() - timedelta(days=7)
    try:
        with open(ALERT_LOG, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    a = json.loads(line)
                    ts = datetime.fromisoformat(a.get("timestamp","")[:19])
                    if ts >= cutoff:
                        alerts.append(a)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return alerts


def _analyze(events: list, alerts: list) -> dict:
    # Attacks per hour (last 24h)
    now = datetime.now()
    hourly = defaultdict(int)
    for e in events:
        try:
            ts = datetime.fromisoformat(e.get("timestamp","")[:19])
            if ts >= now - timedelta(hours=24):
                hour_key = ts.strftime("%H:00")
                hourly[hour_key] += 1
        except Exception:
            pass
    # Fill missing hours
    hours_24 = []
    counts_24 = []
    for i in range(23, -1, -1):
        h = (now - timedelta(hours=i)).strftime("%H:00")
        hours_24.append(h)
        counts_24.append(hourly.get(h, 0))

    # Daily timeline (last 7 days)
    daily = defaultdict(int)
    for e in events:
        try:
            ts = datetime.fromisoformat(e.get("timestamp","")[:19])
            daily[ts.strftime("%m/%d")] += 1
        except Exception:
            pass
    days_7   = [(now - timedelta(days=i)).strftime("%m/%d") for i in range(6,-1,-1)]
    counts_7 = [daily.get(d, 0) for d in days_7]

    # Service breakdown
    services = defaultdict(int)
    for e in events:
        svc = e.get("service","?")
        if svc: services[svc] += 1

    # Top countries
    countries = defaultdict(int)
    for e in events:
        c = e.get("country","Unknown")
        if c and c != "Local/Private": countries[c] += 1
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:8]

    # Top SSH commands
    commands = defaultdict(int)
    for e in events:
        if e.get("service") == "SSH" and e.get("command"):
            cmd = e["command"].strip().split()[0] if e["command"].strip().split() else e["command"]
            commands[cmd[:20]] += 1
    top_commands = sorted(commands.items(), key=lambda x: x[1], reverse=True)[:10]

    # Alert severity
    sev_counts = defaultdict(int)
    for a in alerts:
        sev_counts[a.get("severity","?")] += 1

    # Top IPs
    ips = defaultdict(int)
    for e in events:
        ip = e.get("ip","")
        if ip: ips[ip] += 1
    top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:6]

    # Login stats
    login_ok   = sum(1 for e in events if "SUCCESS" in e.get("event",""))
    login_fail = sum(1 for e in events if "FAIL" in e.get("event",""))

    return {
        "total":          len(events),
        "hours_24":       hours_24,
        "counts_24":      counts_24,
        "days_7":         days_7,
        "counts_7":       counts_7,
        "services":       dict(services),
        "top_countries":  top_countries,
        "top_commands":   top_commands,
        "sev_counts":     dict(sev_counts),
        "top_ips":        top_ips,
        "login_ok":       login_ok,
        "login_fail":     login_fail,
        "total_alerts":   len(alerts),
    }


# ── Canvas chart helpers ───────────────────────────────────────────────────────
class ChartCanvas(tk.Canvas):
    """Base canvas with chart drawing utilities."""

    def __init__(self, parent, w, h, title="", **kw):
        super().__init__(parent, width=w, height=h,
                         bg=C["panel"], highlightthickness=0, **kw)
        self.cw    = w
        self.ch    = h
        self.title = title
        # Title
        if title:
            self.create_text(w//2, 14, text=title,
                             fill=C["accent"], font=SUI_B, anchor="n")

    def _pad(self):
        return 32, 24, 28, 40  # top, right, bottom, left

    def bar_chart(self, labels, values, colors=None, title_y_offset=0):
        """Vertical bar chart."""
        self.delete("chart")
        if not values or max(values) == 0:
            self.create_text(self.cw//2, self.ch//2,
                             text="No data yet", fill=C["muted"],
                             font=SUI, tags="chart")
            return

        pt, pr, pb, pl = self._pad()
        pt += 20 + title_y_offset
        area_w = self.cw - pl - pr
        area_h = self.ch - pt - pb
        max_v  = max(values) or 1
        n      = len(values)
        bar_w  = max(4, area_w // n - 3)
        colors = colors or [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]

        # Y axis gridlines
        for i in range(5):
            y = pt + area_h - int(area_h * i / 4)
            self.create_line(pl, y, self.cw - pr, y,
                             fill=C["border"], dash=(3,3), tags="chart")
            val_lbl = int(max_v * i / 4)
            self.create_text(pl - 4, y, text=str(val_lbl),
                             fill=C["muted"], font=("Consolas",7),
                             anchor="e", tags="chart")

        # Bars
        for i, (lbl, val, col) in enumerate(zip(labels, values, colors)):
            x0 = pl + i * (area_w // n) + (area_w // n - bar_w) // 2
            x1 = x0 + bar_w
            bar_h = int(area_h * val / max_v)
            y0 = pt + area_h - bar_h
            y1 = pt + area_h

            # Bar with gradient effect (two rectangles)
            self.create_rectangle(x0, y0, x1, y1,
                                  fill=col, outline="", tags="chart")
            # Highlight top edge
            self.create_line(x0, y0, x1, y0,
                             fill="#ffffff", width=1, tags="chart")

            # Value on top
            if val > 0:
                self.create_text((x0+x1)//2, y0 - 4, text=str(val),
                                 fill=C["text"], font=("Consolas",7),
                                 anchor="s", tags="chart")
            # Label below
            lbl_short = lbl[:6] if len(lbl) > 6 else lbl
            self.create_text((x0+x1)//2, y1 + 4, text=lbl_short,
                             fill=C["muted"], font=("Consolas",7),
                             anchor="n", tags="chart")

    def hbar_chart(self, labels, values, colors=None):
        """Horizontal bar chart."""
        self.delete("chart")
        if not values or max(values) == 0:
            self.create_text(self.cw//2, self.ch//2,
                             text="No data yet", fill=C["muted"],
                             font=SUI, tags="chart")
            return

        pt, pr, pb, pl = 36, 16, 12, 16
        label_w = 110
        area_w  = self.cw - pl - label_w - pr
        n       = len(values)
        row_h   = max(14, (self.ch - pt - pb) // max(n, 1))
        max_v   = max(values) or 1
        colors  = colors or [CHART_COLORS[i % len(CHART_COLORS)] for i in range(n)]

        for i, (lbl, val, col) in enumerate(zip(labels, values, colors)):
            y_center = pt + i * row_h + row_h // 2
            bar_w = int(area_w * val / max_v)

            # Label
            self.create_text(pl + label_w - 6, y_center,
                             text=lbl[:16], fill=C["text"],
                             font=("Consolas", 8), anchor="e", tags="chart")
            # Bar
            x0 = pl + label_w
            self.create_rectangle(x0, y_center - 7,
                                  x0 + bar_w, y_center + 7,
                                  fill=col, outline="", tags="chart")
            # Value
            self.create_text(x0 + bar_w + 4, y_center,
                             text=str(val), fill=col,
                             font=("Consolas", 8), anchor="w", tags="chart")

    def pie_chart(self, labels, values, colors=None):
        """Pie / donut chart with legend."""
        self.delete("chart")
        total = sum(values)
        if total == 0:
            self.create_text(self.cw//2, self.ch//2,
                             text="No data yet", fill=C["muted"],
                             font=SUI, tags="chart")
            return

        colors = colors or [CHART_COLORS[i % len(CHART_COLORS)] for i in range(len(values))]
        cx = self.cw // 2 - 30
        cy = self.ch // 2 + 10
        r  = min(cx - 10, cy - 30, 65)

        # Draw slices
        start = -90.0
        for i, (lbl, val, col) in enumerate(zip(labels, values, colors)):
            extent = 360.0 * val / total
            self.create_arc(cx - r, cy - r, cx + r, cy + r,
                            start=start, extent=extent,
                            fill=col, outline=C["panel"], width=2,
                            tags="chart")
            start += extent

        # Inner circle (donut)
        inner = r * 0.55
        self.create_oval(cx - inner, cy - inner,
                         cx + inner, cy + inner,
                         fill=C["panel"], outline="", tags="chart")
        self.create_text(cx, cy, text=str(total),
                         fill=C["white"], font=("Consolas", 12, "bold"),
                         tags="chart")
        self.create_text(cx, cy + 14, text="total",
                         fill=C["muted"], font=("Consolas", 7),
                         tags="chart")

        # Legend (right side)
        lx = cx + r + 16
        ly_start = cy - r + 10
        for i, (lbl, val, col) in enumerate(zip(labels, values, colors)):
            ly = ly_start + i * 18
            self.create_rectangle(lx, ly - 5, lx + 10, ly + 5,
                                  fill=col, outline="", tags="chart")
            pct = f"{100*val//total}%"
            self.create_text(lx + 14, ly, text=f"{lbl[:10]} {pct}",
                             fill=C["text"], font=("Consolas", 8),
                             anchor="w", tags="chart")

    def line_chart(self, labels, values, color=None):
        """Line chart with area fill."""
        self.delete("chart")
        if not values or max(values) == 0:
            self.create_text(self.cw//2, self.ch//2,
                             text="No data yet", fill=C["muted"],
                             font=SUI, tags="chart")
            return

        color  = color or C["accent"]
        pt, pr, pb, pl = self._pad()
        pt += 20
        area_w = self.cw - pl - pr
        area_h = self.ch - pt - pb
        max_v  = max(values) or 1
        n      = len(values)

        # Grid
        for i in range(4):
            y = pt + int(area_h * i / 3)
            self.create_line(pl, y, self.cw - pr, y,
                             fill=C["border"], dash=(3,3), tags="chart")

        # Build points
        pts = []
        for i, val in enumerate(values):
            x = pl + int(area_w * i / max(n - 1, 1))
            y = pt + area_h - int(area_h * val / max_v)
            pts.append((x, y))

        # Area fill (polygon)
        if len(pts) >= 2:
            poly = list(pts) + [(pts[-1][0], pt + area_h),
                                 (pts[0][0],  pt + area_h)]
            flat = [coord for p in poly for coord in p]
            # Simulate transparency with darker color
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            fill_col = f"#{r//4:02x}{g//4:02x}{b//4:02x}"
            self.create_polygon(flat, fill=fill_col, outline="", tags="chart")

        # Line
        if len(pts) >= 2:
            flat_pts = [coord for p in pts for coord in p]
            self.create_line(flat_pts, fill=color, width=2,
                             smooth=True, tags="chart")

        # Dots + labels
        step = max(1, n // 7)
        for i, (x, y) in enumerate(pts):
            self.create_oval(x-3, y-3, x+3, y+3,
                             fill=color, outline=C["panel"],
                             width=1, tags="chart")
            if i % step == 0:
                self.create_text(x, pt + area_h + 4,
                                 text=labels[i], fill=C["muted"],
                                 font=("Consolas", 7), anchor="n",
                                 tags="chart")
                if values[i] > 0:
                    self.create_text(x, y - 8, text=str(values[i]),
                                     fill=color, font=("Consolas", 7),
                                     anchor="s", tags="chart")


# ── KPI Card ──────────────────────────────────────────────────────────────────
class KPICard(tk.Frame):
    def __init__(self, parent, title, value, subtitle="",
                 color=None, **kw):
        color = color or C["accent"]
        super().__init__(parent, bg=C["panel2"],
                         highlightbackground=color,
                         highlightthickness=2, **kw)
        # Top accent line
        tk.Frame(self, bg=color, height=3).pack(fill="x")

        tk.Label(self, text=title, font=("Segoe UI", 8),
                 bg=C["panel2"], fg=C["muted"]).pack(pady=(8,0))

        self.val_lbl = tk.Label(self, text=str(value),
                                font=("Consolas", 22, "bold"),
                                bg=C["panel2"], fg=color)
        self.val_lbl.pack()

        if subtitle:
            tk.Label(self, text=subtitle, font=("Segoe UI", 8),
                     bg=C["panel2"], fg=C["muted"]).pack(pady=(0,8))

    def update_val(self, value, subtitle=""):
        self.val_lbl.config(text=str(value))


# ── Main Dashboard Window ─────────────────────────────────────────────────────
class AnalyticsDashboard(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("📊 Analytics Dashboard")
        self.configure(bg=C["bg"])
        self.geometry("1280x800")
        self.minsize(1000, 680)
        self._refresh_job = None
        self._build()
        self._refresh()
        self._schedule()

    def _build(self):
        # ── Top bar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        tb.pack(fill="x")

        tk.Label(tb, text="  📊  HONEYPOT ANALYTICS DASHBOARD",
                 font=SUI_H, bg=C["panel"],
                 fg=C["accent"]).pack(side="left", pady=8, padx=4)

        self.clock_v = tk.StringVar()
        tk.Label(tb, textvariable=self.clock_v,
                 font=MONO, bg=C["panel"],
                 fg=C["muted"]).pack(side="right", padx=12)

        self.last_v = tk.StringVar(value="")
        tk.Label(tb, textvariable=self.last_v,
                 font=MONO, bg=C["panel"],
                 fg=C["muted"]).pack(side="right", padx=4)

        tk.Button(tb, text="🔄 Refresh Now",
                  font=SUI_B, bg=C["border"], fg=C["text"],
                  relief="flat", padx=10, pady=4,
                  command=self._refresh).pack(side="right", padx=8)

        # ── KPI row ───────────────────────────────────────────────────────────
        kpi_f = tk.Frame(self, bg=C["bg"])
        kpi_f.pack(fill="x", padx=10, pady=(8, 4))

        self.kpi_total  = KPICard(kpi_f, "TOTAL EVENTS",   "0",
                                   color=C["accent"])
        self.kpi_alerts = KPICard(kpi_f, "TOTAL ALERTS",   "0",
                                   color=C["danger"])
        self.kpi_ips    = KPICard(kpi_f, "UNIQUE IPs",     "0",
                                   color=C["warn"])
        self.kpi_ok     = KPICard(kpi_f, "LOGINS SUCCESS", "0",
                                   color=C["green"])
        self.kpi_fail   = KPICard(kpi_f, "LOGINS FAILED",  "0",
                                   color=C["orange"])
        self.kpi_sess   = KPICard(kpi_f, "SESSIONS REC.",  "0",
                                   color=C["purple"])

        for kpi in (self.kpi_total, self.kpi_alerts, self.kpi_ips,
                    self.kpi_ok, self.kpi_fail, self.kpi_sess):
            kpi.pack(side="left", fill="both", expand=True, padx=3)

        # ── Row 1: Attacks per hour + Timeline ────────────────────────────────
        r1 = tk.Frame(self, bg=C["bg"])
        r1.pack(fill="both", expand=True, padx=10, pady=3)

        # Attacks per hour
        f1 = tk.Frame(r1, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        f1.pack(side="left", fill="both", expand=True, padx=(0,3))
        tk.Label(f1, text="⏱  ATTACKS PER HOUR (Last 24h)",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack()
        self.chart_hourly = ChartCanvas(f1, 580, 160)
        self.chart_hourly.pack(padx=4, pady=(0,4))

        # 7-day timeline
        f2 = tk.Frame(r1, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        f2.pack(side="left", fill="both", expand=True)
        tk.Label(f2, text="📅  ATTACK TIMELINE (Last 7 Days)",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack()
        self.chart_timeline = ChartCanvas(f2, 440, 160)
        self.chart_timeline.pack(padx=4, pady=(0,4))

        # ── Row 2: Service pie + Countries + Commands ─────────────────────────
        r2 = tk.Frame(self, bg=C["bg"])
        r2.pack(fill="both", expand=True, padx=10, pady=3)

        # Service breakdown
        f3 = tk.Frame(r2, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        f3.pack(side="left", fill="both", expand=True, padx=(0,3))
        tk.Label(f3, text="🔌  SERVICE BREAKDOWN",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack()
        self.chart_service = ChartCanvas(f3, 330, 170)
        self.chart_service.pack(padx=4, pady=(0,4))

        # Top countries
        f4 = tk.Frame(r2, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        f4.pack(side="left", fill="both", expand=True, padx=(0,3))
        tk.Label(f4, text="🌍  TOP COUNTRIES",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack()
        self.chart_country = ChartCanvas(f4, 340, 170)
        self.chart_country.pack(padx=4, pady=(0,4))

        # Alert severity + SSH commands
        f5 = tk.Frame(r2, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        f5.pack(side="left", fill="both", expand=True)
        tk.Label(f5, text="🚨  ALERT SEVERITY",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack()
        self.chart_severity = ChartCanvas(f5, 300, 80)
        self.chart_severity.pack(padx=4, pady=(0,2))
        tk.Frame(f5, bg=C["border"], height=1).pack(fill="x", padx=4)
        tk.Label(f5, text="💻  TOP SSH COMMANDS",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=4).pack()
        self.chart_cmds = ChartCanvas(f5, 300, 80)
        self.chart_cmds.pack(padx=4, pady=(0,4))

        # ── Status bar ─────────────────────────────────────────────────────────
        sb = tk.Frame(self, bg="#060810", height=22)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        tk.Label(sb,
                 text="  Auto-refreshes every 10 seconds  ·  "
                      "Data from logs/honeypot_master.log",
                 font=("Segoe UI", 8), bg="#060810",
                 fg=C["muted"]).pack(side="left")

        self._update_clock()

    # ── Data refresh ──────────────────────────────────────────────────────────
    def _refresh(self):
        events = _load_events(168)
        alerts = _load_alerts()
        data   = _analyze(events, alerts)

        # Count sessions
        sess_count = 0
        if os.path.exists("sessions"):
            sess_count = len([f for f in os.listdir("sessions")
                              if f.endswith(".cast")])

        # Update KPIs
        self.kpi_total.update_val(f"{data['total']:,}")
        self.kpi_alerts.update_val(f"{data['total_alerts']:,}")
        self.kpi_ips.update_val(str(len(data['top_ips'])))
        self.kpi_ok.update_val(str(data['login_ok']))
        self.kpi_fail.update_val(str(data['login_fail']))
        self.kpi_sess.update_val(str(sess_count))

        # Chart 1: Attacks per hour
        h_labels = data["hours_24"][::2]   # every 2 hours for readability
        h_vals   = data["counts_24"][::2]
        colors_h = [C["accent"] if v > 0 else C["border"] for v in h_vals]
        self.chart_hourly.bar_chart(h_labels, h_vals, colors_h)

        # Chart 2: 7-day timeline
        self.chart_timeline.line_chart(
            data["days_7"], data["counts_7"], color=C["green"]
        )

        # Chart 3: Service breakdown
        svcs = data["services"]
        if svcs:
            s_labels = list(svcs.keys())
            s_vals   = list(svcs.values())
            s_colors = [SVC_COLORS.get(s, CHART_COLORS[i % len(CHART_COLORS)])
                        for i, s in enumerate(s_labels)]
            self.chart_service.pie_chart(s_labels, s_vals, s_colors)
        else:
            self.chart_service.pie_chart([], [])

        # Chart 4: Top countries
        if data["top_countries"]:
            c_labels = [c[0][:14] for c in data["top_countries"]]
            c_vals   = [c[1]      for c in data["top_countries"]]
            self.chart_country.hbar_chart(c_labels, c_vals)
        else:
            self.chart_country.hbar_chart([], [])

        # Chart 5a: Alert severity
        sev_order  = ["CRITICAL","HIGH","MEDIUM","LOW"]
        sev_vals   = [data["sev_counts"].get(s, 0) for s in sev_order]
        sev_colors = [SEV_COLORS[s] for s in sev_order]
        self.chart_severity.bar_chart(sev_order, sev_vals, sev_colors)

        # Chart 5b: Top SSH commands
        if data["top_commands"]:
            cmd_labels = [c[0][:8] for c in data["top_commands"][:8]]
            cmd_vals   = [c[1]     for c in data["top_commands"][:8]]
            self.chart_cmds.bar_chart(cmd_labels, cmd_vals)
        else:
            self.chart_cmds.bar_chart([], [])

        # Update last refresh time
        self.last_v.set(f"Updated: {datetime.now().strftime('%H:%M:%S')}")

    def _schedule(self):
        self._refresh_job = self.after(10000, lambda: [self._refresh(), self._schedule()])

    def _update_clock(self):
        self.clock_v.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    def destroy(self):
        if self._refresh_job:
            try: self.after_cancel(self._refresh_job)
            except Exception: pass
        super().destroy()


# ── Public API ────────────────────────────────────────────────────────────────
def open_dashboard(parent=None):
    if parent is None:
        root = tk.Tk()
        root.withdraw()
        d = AnalyticsDashboard(root)
        root.mainloop()
    else:
        d = AnalyticsDashboard(parent)
        d.focus_force()
        return d


if __name__ == "__main__":
    open_dashboard()