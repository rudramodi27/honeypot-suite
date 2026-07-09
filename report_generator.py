"""
report_generator.py — Auto PDF Report Generator
Generates a professional attack intelligence report from honeypot logs.

Usage:
  python report_generator.py              → generates today's report
  python report_generator.py --days 7    → last 7 days
  python report_generator.py --out report.pdf

Can also be called programmatically:
  from report_generator import generate_report
  path = generate_report()
"""

import os, json, sys, argparse
from datetime import datetime, timedelta
from collections import defaultdict

os.makedirs("exports", exist_ok=True)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm, mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import (
        BaseDocTemplate, Frame, PageTemplate,
        Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether, NextPageTemplate
    )
    from reportlab.pdfgen import canvas as pdfcanvas
    RL_OK = True
except ImportError:
    RL_OK = False

W, H = A4

# ── Colors ────────────────────────────────────────────────────────────────────
NAVY    = colors.HexColor("#0b1629")
NAVY2   = colors.HexColor("#111f36")
BLUE    = colors.HexColor("#1e6fcf")
SKY     = colors.HexColor("#4da3ff")
GOLD    = colors.HexColor("#f0a500")
GREEN   = colors.HexColor("#27ae60")
RED     = colors.HexColor("#e05555")
ORANGE  = colors.HexColor("#e67e22")
LGRAY   = colors.HexColor("#dce8f5")
MGRAY   = colors.HexColor("#5a7a9a")
DGRAY   = colors.HexColor("#1e3250")
WHITE   = colors.white
BLACK   = colors.HexColor("#1a1a2e")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#cc0000"),
    "HIGH":     colors.HexColor("#e05555"),
    "MEDIUM":   colors.HexColor("#e67e22"),
    "LOW":      colors.HexColor("#f0a500"),
}


# ── Load and parse logs ────────────────────────────────────────────────────────
def _load_events(days: int = 1) -> list[dict]:
    master = "logs/honeypot_master.log"
    cutoff = datetime.now() - timedelta(days=days)
    events = []
    try:
        with open(master) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    ts_str = e.get("timestamp", "")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str[:19])
                        if ts >= cutoff:
                            events.append(e)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return events


def _load_alerts(days: int = 1) -> list[dict]:
    path = "alerts/alerts.log"
    cutoff = datetime.now() - timedelta(days=days)
    alerts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                    ts_str = a.get("timestamp", "")
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str[:19])
                        if ts >= cutoff:
                            alerts.append(a)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return alerts


def _load_sessions(days: int = 1) -> list[dict]:
    import os
    sessions = []
    sess_dir = "sessions"
    if not os.path.exists(sess_dir):
        return sessions
    cutoff = datetime.now() - timedelta(days=days)
    for fname in os.listdir(sess_dir):
        if not fname.endswith(".cast"):
            continue
        try:
            path = os.path.join(sess_dir, fname)
            with open(path) as f:
                header = json.loads(f.readline())
            ts = datetime.fromtimestamp(header.get("timestamp", 0))
            if ts >= cutoff:
                sessions.append({
                    "file":  path,
                    "title": header.get("title", fname),
                    "ts":    ts,
                })
        except Exception:
            pass
    return sessions


def _analyze(events: list, alerts: list) -> dict:
    by_service  = defaultdict(int)
    by_ip       = defaultdict(int)
    by_country  = defaultdict(int)
    passwords   = defaultdict(int)
    usernames   = defaultdict(int)
    commands    = defaultdict(int)
    payloads    = []
    scanners    = defaultdict(int)
    by_alert    = defaultdict(int)
    by_sev      = defaultdict(int)
    login_ok    = 0
    login_fail  = 0

    for e in events:
        svc = e.get("service", "?")
        by_service[svc] += 1
        ip = e.get("ip", "?")
        by_ip[ip] += 1
        country = e.get("country", "Unknown")
        by_country[country] += 1

        evt = e.get("event", "")
        if "SUCCESS" in evt:
            login_ok += 1
        if "FAILURE" in evt or "FAIL" in evt:
            login_fail += 1
        if pwd := e.get("password"):
            passwords[pwd] += 1
        if usr := e.get("username"):
            usernames[usr] += 1
        if cmd := e.get("command"):
            base = cmd.strip().split()[0] if cmd.strip().split() else cmd
            commands[base] += 1
        if pay := e.get("payload"):
            payloads.append(pay[:80])
        if tool := e.get("tool"):
            scanners[tool] += 1

    for a in alerts:
        by_alert[a.get("type", "?")] += 1
        by_sev[a.get("severity", "?")] += 1

    return {
        "total_events":   len(events),
        "total_alerts":   len(alerts),
        "login_success":  login_ok,
        "login_fail":     login_fail,
        "by_service":     sorted(by_service.items(), key=lambda x: x[1], reverse=True),
        "top_ips":        sorted(by_ip.items(),      key=lambda x: x[1], reverse=True)[:10],
        "top_countries":  sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10],
        "top_passwords":  sorted(passwords.items(),  key=lambda x: x[1], reverse=True)[:10],
        "top_usernames":  sorted(usernames.items(),  key=lambda x: x[1], reverse=True)[:10],
        "top_commands":   sorted(commands.items(),   key=lambda x: x[1], reverse=True)[:10],
        "payloads":       payloads[:10],
        "scanners":       sorted(scanners.items(),   key=lambda x: x[1], reverse=True)[:10],
        "alert_types":    sorted(by_alert.items(),   key=lambda x: x[1], reverse=True),
        "alert_severity": dict(by_sev),
    }


# ── Styles ────────────────────────────────────────────────────────────────────
def _styles():
    return {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold",
                              fontSize=22, textColor=WHITE,
                              leading=28, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold",
                              fontSize=14, textColor=BLUE,
                              leading=20, spaceBefore=16, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold",
                              fontSize=11, textColor=SKY,
                              leading=16, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica",
                                fontSize=10, textColor=BLACK,
                                leading=15, spaceAfter=6,
                                alignment=TA_JUSTIFY),
        "mono": ParagraphStyle("mono", fontName="Courier",
                                fontSize=9, textColor=BLACK,
                                leading=13, spaceAfter=3,
                                backColor=colors.HexColor("#eef4fc"),
                                leftIndent=8),
        "muted": ParagraphStyle("muted", fontName="Helvetica",
                                 fontSize=9, textColor=MGRAY,
                                 leading=13, alignment=TA_CENTER),
        "kpi_val": ParagraphStyle("kpi_val", fontName="Helvetica-Bold",
                                   fontSize=26, textColor=BLUE,
                                   leading=30, alignment=TA_CENTER),
        "kpi_lbl": ParagraphStyle("kpi_lbl", fontName="Helvetica",
                                   fontSize=9, textColor=MGRAY,
                                   leading=12, alignment=TA_CENTER),
    }


# ── Page callbacks ─────────────────────────────────────────────────────────────
def _cover_canvas(c: pdfcanvas.Canvas, doc):
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(BLUE)
    c.rect(0, 0, 6*mm, H, fill=1, stroke=0)
    c.setFillColor(GOLD)
    c.rect(6*mm, H-3*mm, W, 3*mm, fill=1, stroke=0)
    c.setFillColor(NAVY2)
    c.rect(0, 0, W, 30*mm, fill=1, stroke=0)
    # Footer
    c.setFont("Helvetica", 8)
    c.setFillColor(MGRAY)
    c.drawString(16*mm, 18*mm,
        "Laxmi Chit Fund  ·  Honeypot Intelligence Report")
    c.drawRightString(W-12*mm, 18*mm,
        f"Generated: {datetime.now().strftime('%d %B %Y %H:%M')}")
    c.drawString(16*mm, 11*mm,
        "CONFIDENTIAL — For authorized cybersecurity research use only")
    # Decorative circle
    c.setStrokeColor(BLUE)
    c.setFillColor(colors.transparent)
    c.setLineWidth(1.5)
    c.circle(W-38*mm, H-38*mm, 52*mm)
    c.setLineWidth(0.5)
    c.setStrokeColor(SKY)
    c.circle(W-38*mm, H-38*mm, 68*mm)
    c.restoreState()


def _normal_canvas(c: pdfcanvas.Canvas, doc):
    c.saveState()
    c.setFillColor(BLUE)
    c.rect(0, 0, 3*mm, H, fill=1, stroke=0)
    c.setFillColor(DGRAY)
    c.rect(3*mm, H-14*mm, W, 0.5*mm, fill=1, stroke=0)
    c.setFont("Helvetica", 8)
    c.setFillColor(MGRAY)
    c.drawString(10*mm, H-10*mm,
        "Laxmi Chit Fund Honeypot Suite — Attack Intelligence Report")
    c.drawRightString(W-10*mm, H-10*mm, f"Page {doc.page}")
    c.rect(3*mm, 14*mm, W, 0.5*mm, fill=1, stroke=0)
    c.drawString(10*mm, 9*mm, "Confidential — Research Use Only")
    c.drawRightString(W-10*mm, 9*mm,
        datetime.now().strftime("%B %Y"))
    c.restoreState()


# ── Table builders ─────────────────────────────────────────────────────────────
def _header_table(headers, rows, col_widths=None):
    S = _styles()
    data = [[Paragraph(h, ParagraphStyle("th", fontName="Helvetica-Bold",
                                          fontSize=9, textColor=WHITE))
             for h in headers]] + \
           [[Paragraph(str(c), S["body"]) for c in row] for row in rows]
    if not col_widths:
        col_widths = [(W - 36*mm) / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  NAVY),
        ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f0f6ff")]),
        ("GRID",          (0,0), (-1,-1), 0.4, DGRAY),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,1), (-1,-1), 9),
    ]))
    return t


def _kpi_card(value: str, label: str, color=BLUE):
    S = _styles()
    kv = ParagraphStyle("kv", fontName="Helvetica-Bold",
                         fontSize=26, textColor=color,
                         leading=30, alignment=TA_CENTER)
    kl = ParagraphStyle("kl", fontName="Helvetica",
                         fontSize=9, textColor=MGRAY,
                         leading=12, alignment=TA_CENTER)
    data = [[Paragraph(str(value), kv)], [Paragraph(label, kl)]]
    t = Table(data, colWidths=[42*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#f0f6ff")),
        ("BOX",          (0,0), (-1,-1), 1,    DGRAY),
        ("LINEABOVE",    (0,0), (-1,0),  2.5,  color),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
    ]))
    return t


def _info_box(text: str, bg=colors.HexColor("#e8f3ff"), border=BLUE):
    S = _styles()
    data = [[Paragraph(text, S["body"])]]
    t = Table(data, colWidths=[W - 36*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("BOX",           (0,0), (-1,-1), 1, border),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    return t


def _bar(value: int, max_val: int, width_mm: float = 60) -> str:
    if max_val == 0:
        return "0"
    filled = int(value / max_val * 20)
    return "█" * filled + "░" * (20 - filled) + f"  {value}"


# ── Build story ────────────────────────────────────────────────────────────────
def _build_story(data: dict, analysis: dict, days: int,
                 sessions: list) -> list:
    S     = _styles()
    story = []

    now = datetime.now()

    # ── COVER ──────────────────────────────────────────────────────────────────
    story.append(Spacer(1, H * 0.15))
    story.append(Paragraph(
        "HONEYPOT SUITE",
        ParagraphStyle("ct", fontName="Helvetica",
                       fontSize=11, textColor=GOLD,
                       leading=16, letterSpacing=4)
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Attack Intelligence<br/>Report",
        ParagraphStyle("ct2", fontName="Helvetica-Bold",
                       fontSize=28, textColor=WHITE, leading=36)
    ))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Period: Last {days} day{'s' if days > 1 else ''}  ·  "
        f"Generated: {now.strftime('%d %B %Y %H:%M')}",
        ParagraphStyle("cs", fontName="Helvetica",
                       fontSize=12, textColor=SKY, leading=18)
    ))
    story.append(Spacer(1, 32))
    for k, v in [
        ("Total Events",    f"{analysis['total_events']:,}"),
        ("Total Alerts",    f"{analysis['total_alerts']:,}"),
        ("Unique IPs",      f"{len(analysis['top_ips'])}+"),
        ("Sessions Recorded", str(len(sessions))),
        ("Report Period",   f"{days} day(s)"),
        ("Institution",     "Laxmi Chit Fund (Fictional Entity)"),
    ]:
        story.append(Paragraph(
            f'<font color="#5a7a9a">{k}:</font>  '
            f'<font color="#dce8f5"><b>{v}</b></font>',
            ParagraphStyle("ml", fontName="Helvetica",
                           fontSize=10, textColor=MGRAY, leading=18)
        ))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))

    # KPI grid
    kpis = [
        (_kpi_card(f"{analysis['total_events']:,}", "Total Events",   BLUE),
         _kpi_card(f"{analysis['total_alerts']:,}", "Total Alerts",   RED),
         _kpi_card(str(len(analysis['top_ips'])),   "Unique IPs",     ORANGE),
         _kpi_card(str(len(sessions)), "Sessions Recorded", GREEN)),
    ]
    kpi_row = [
        _kpi_card(f"{analysis['total_events']:,}", "Total Events",    BLUE),
        _kpi_card(f"{analysis['total_alerts']:,}", "Total Alerts",    RED),
        _kpi_card(str(len(analysis['top_ips'])),   "Unique IPs",      ORANGE),
        _kpi_card(str(len(sessions)), "Sessions Recorded",            GREEN),
    ]
    kpi_t = Table([kpi_row], colWidths=[42*mm]*4,
                  hAlign="LEFT")
    kpi_t.setStyle(TableStyle([
        ("LEFTPADDING",  (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING",   (0,0), (-1,-1), 0),
    ]))
    story.append(kpi_t)
    story.append(Spacer(1, 12))

    # Alert severity breakdown
    sev_data = analysis.get("alert_severity", {})
    crit = sev_data.get("CRITICAL", 0)
    high = sev_data.get("HIGH", 0)
    med  = sev_data.get("MEDIUM", 0)
    low  = sev_data.get("LOW", 0)

    story.append(Paragraph(
        f"During the reporting period the honeypot recorded "
        f"<b>{analysis['total_events']:,}</b> total events across all services. "
        f"The alert system triggered <b>{analysis['total_alerts']:,}</b> security alerts "
        f"including <b>{crit}</b> CRITICAL, <b>{high}</b> HIGH, "
        f"<b>{med}</b> MEDIUM, and <b>{low}</b> LOW severity events. "
        f"A total of <b>{analysis['login_fail']:,}</b> failed login attempts "
        f"and <b>{analysis['login_success']:,}</b> successful authentications "
        f"were recorded across HTTP, FTP, and SSH services.",
        S["body"]
    ))
    story.append(Spacer(1, 8))

    # Alert severity table
    if sev_data:
        sev_rows = [(sev, str(cnt)) for sev, cnt in
                    sorted(sev_data.items(),
                           key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0])
                           if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99)]
        t = _header_table(["Severity", "Count"], sev_rows,
                          col_widths=[60*mm, 40*mm])
        story.append(t)

    story.append(PageBreak())

    # ── ATTACK SOURCES ─────────────────────────────────────────────────────────
    story.append(Paragraph("Attack Sources", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))

    # Top IPs
    story.append(Paragraph("Top Attacking IP Addresses", S["h3"]))
    if analysis["top_ips"]:
        max_c = analysis["top_ips"][0][1] if analysis["top_ips"] else 1
        rows = [(ip, str(cnt), _bar(cnt, max_c))
                for ip, cnt in analysis["top_ips"]]
        story.append(_header_table(
            ["IP Address", "Events", "Activity"],
            rows,
            col_widths=[50*mm, 20*mm, 100*mm]
        ))
    else:
        story.append(_info_box("No attack data recorded yet."))

    story.append(Spacer(1, 10))

    # Top countries
    story.append(Paragraph("Attack Origins by Country/Region", S["h3"]))
    if analysis["top_countries"]:
        max_c = analysis["top_countries"][0][1] if analysis["top_countries"] else 1
        rows = [(c, str(n), _bar(n, max_c))
                for c, n in analysis["top_countries"]]
        story.append(_header_table(
            ["Country/Region", "Events", "Activity"],
            rows,
            col_widths=[50*mm, 20*mm, 100*mm]
        ))

    story.append(PageBreak())

    # ── SERVICE BREAKDOWN ──────────────────────────────────────────────────────
    story.append(Paragraph("Service Activity Breakdown", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))
    if analysis["by_service"]:
        max_c = analysis["by_service"][0][1] if analysis["by_service"] else 1
        rows = [(svc, str(cnt), _bar(cnt, max_c))
                for svc, cnt in analysis["by_service"]]
        story.append(_header_table(
            ["Service", "Events", "Activity"],
            rows,
            col_widths=[40*mm, 25*mm, 105*mm]
        ))
    story.append(Spacer(1, 10))

    # ── CREDENTIALS ────────────────────────────────────────────────────────────
    story.append(Paragraph("Credential Intelligence", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))

    if analysis["top_passwords"] or analysis["top_usernames"]:
        cols = []
        if analysis["top_usernames"]:
            un_rows = [(u, str(c)) for u, c in analysis["top_usernames"]]
            cols.append(_header_table(["Username", "Attempts"], un_rows,
                                       col_widths=[50*mm, 20*mm]))
        if analysis["top_passwords"]:
            pw_rows = [(p[:20], str(c)) for p, c in analysis["top_passwords"]]
            cols.append(_header_table(["Password", "Attempts"], pw_rows,
                                       col_widths=[50*mm, 20*mm]))
        if len(cols) == 2:
            t = Table([cols], colWidths=[(W-36*mm)/2]*2)
            t.setStyle(TableStyle([
                ("LEFTPADDING",  (0,0), (-1,-1), 4),
                ("RIGHTPADDING", (0,0), (-1,-1), 4),
                ("VALIGN",       (0,0), (-1,-1), "TOP"),
            ]))
            story.append(t)
        else:
            for col in cols:
                story.append(col)
    else:
        story.append(_info_box("No credential data recorded yet."))

    story.append(PageBreak())

    # ── ALERTS ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("Alert Analysis", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))
    if analysis["alert_types"]:
        rows = [(atype, str(cnt)) for atype, cnt in analysis["alert_types"]]
        story.append(_header_table(
            ["Alert Type", "Count"], rows,
            col_widths=[100*mm, 30*mm]
        ))
    else:
        story.append(_info_box("No alerts recorded yet."))

    # Scanners
    story.append(Paragraph("Detected Scanning Tools", S["h3"]))
    if analysis["scanners"]:
        rows = [(tool, str(cnt)) for tool, cnt in analysis["scanners"]]
        story.append(_header_table(
            ["Tool", "Detections"], rows,
            col_widths=[80*mm, 30*mm]
        ))
    else:
        story.append(Paragraph(
            "No automated scanning tools detected.", S["body"]
        ))

    # Payloads
    if analysis["payloads"]:
        story.append(Paragraph("Sample Captured Payloads", S["h3"]))
        for p in analysis["payloads"][:8]:
            story.append(Paragraph(p[:100], S["mono"]))

    story.append(PageBreak())

    # ── SSH COMMANDS ────────────────────────────────────────────────────────────
    story.append(Paragraph("SSH Command Intelligence", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))
    if analysis["top_commands"]:
        rows = [(cmd, str(cnt)) for cmd, cnt in analysis["top_commands"]]
        story.append(_header_table(
            ["Command", "Executions"], rows,
            col_widths=[80*mm, 30*mm]
        ))
    else:
        story.append(_info_box("No SSH command data recorded yet."))

    # Sessions
    story.append(Paragraph("Recorded Attacker Sessions", S["h3"]))
    if sessions:
        rows = [(s["title"][:60], s["ts"].strftime("%Y-%m-%d %H:%M"))
                for s in sessions[:15]]
        story.append(_header_table(
            ["Session Title", "Timestamp"], rows,
            col_widths=[120*mm, 40*mm]
        ))
        story.append(Paragraph(
            f"Replay sessions using: "
            f"python session_recorder.py replay sessions/<file>.cast",
            S["mono"]
        ))
    else:
        story.append(Paragraph("No sessions recorded yet.", S["body"]))

    # ── RECOMMENDATIONS ────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Findings & Recommendations", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE,
                             spaceAfter=8))

    findings = []
    if analysis["total_events"] > 0:
        top_ip = analysis["top_ips"][0][0] if analysis["top_ips"] else "N/A"
        findings.append(
            f"Most active attacker IP: <b>{top_ip}</b> — "
            f"consider adding to network blocklist."
        )
    if analysis["alert_severity"].get("CRITICAL", 0) > 0:
        findings.append(
            f"<b>{analysis['alert_severity']['CRITICAL']} CRITICAL alerts</b> were triggered. "
            f"Webshell uploads or credential traps were accessed — review session recordings."
        )
    if analysis["scanners"]:
        tools = ", ".join(t for t, _ in analysis["scanners"][:3])
        findings.append(
            f"Automated scanning tools detected: <b>{tools}</b>. "
            f"These IPs should be monitored for follow-up manual attacks."
        )
    if analysis["top_passwords"]:
        common = analysis["top_passwords"][0][0]
        findings.append(
            f"Most attempted password: <b>'{common}'</b> — "
            f"confirms attackers use default/common credential lists."
        )
    if not findings:
        findings.append("No significant findings during this period.")

    for f in findings:
        story.append(Paragraph(f"• {f}", S["body"]))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=DGRAY,
                             spaceAfter=8))
    story.append(Paragraph(
        f"Report generated automatically by Laxmi Chit Fund Honeypot Suite v7  ·  "
        f"{datetime.now().strftime('%d %B %Y %H:%M')}  ·  "
        f"Laxmi Chit Fund — Internal Security Research (Fictional)",
        S["muted"]
    ))

    return story


# ── Main generator ────────────────────────────────────────────────────────────
def generate_report(days: int = 1, out_path: str = None) -> str:
    if not RL_OK:
        print("ERROR: reportlab not installed. Run: pip install reportlab")
        return ""

    if not out_path:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"exports/attack_report_{ts}.pdf"

    events   = _load_events(days)
    alerts   = _load_alerts(days)
    sessions = _load_sessions(days)
    analysis = _analyze(events, alerts)

    cover_frame  = Frame(0, 0, W, H,
                          leftPadding=16*mm, rightPadding=12*mm,
                          topPadding=0, bottomPadding=32*mm)
    normal_frame = Frame(8*mm, 18*mm, W-18*mm, H-32*mm,
                          leftPadding=10*mm, rightPadding=8*mm,
                          topPadding=8*mm, bottomPadding=4*mm)

    doc = BaseDocTemplate(out_path, pagesize=A4,
                           leftMargin=0, rightMargin=0,
                           topMargin=0, bottomMargin=0)
    doc.addPageTemplates([
        PageTemplate(id="Cover",  frames=[cover_frame],
                      onPage=_cover_canvas),
        PageTemplate(id="Normal", frames=[normal_frame],
                      onPage=_normal_canvas),
    ])

    story = [NextPageTemplate("Cover")] + \
            [NextPageTemplate("Normal")] + \
            _build_story({}, analysis, days, sessions)

    doc.build(story)
    print(f"[Report] Generated: {out_path}")

    # Phase 1A Evidence Hashing Framework — register the generated PDF
    # as forensic evidence (additive; never blocks report generation).
    try:
        from core.evidence_hashing import register_evidence_file
        ev = register_evidence_file(out_path, source_type="report_export")
        # Phase 1B Chain of Custody — EXPORTED event
        if ev and ev.get("id"):
            from core.chain_of_custody import record_event
            record_event(
                evidence_id=ev["id"],
                action="EXPORTED",
                performed_by="system",
                reason=f"PDF threat report generated (days={days})",
            )
    except Exception:
        pass

    return out_path


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Laxmi Chit Fund Honeypot Report Generator")
    parser.add_argument("--days", type=int, default=1,
                        help="Number of days to include (default: 1)")
    parser.add_argument("--out",  type=str, default=None,
                        help="Output PDF path")
    args = parser.parse_args()
    path = generate_report(days=args.days, out_path=args.out)
    if path:
        print(f"Report saved: {path}")