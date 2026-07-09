"""
main.py — Advanced Honeypot Suite GUI
Features: service controls, live attacker dashboard,
          top IPs/passwords/commands, export buttons, session list
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading, queue, os, sys, time, json
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

import http_honeypot
import ftp_honeypot
import ssh_honeypot
import decoy_services
import logger as hp_log
import alert_system as alerts
import session_recorder as sr
import attack_map as amap
import notifier
import report_generator as rg
import log_viewer
import mitre_attack
import analytics_dashboard as adash
try:
    import docker_sandbox as dsb
    _DSB_OK = True
except ImportError: _DSB_OK = False
import malware_capture as mc
try:
    import ip_enrichment as ipe
    _IPE_OK = True
except ImportError: _IPE_OK = False

# ── Palette ───────────────────────────────────────────────────────────────────
C = {
    "bg":     "#0a0c10", "panel":  "#0f1318", "panel2": "#111820",
    "border": "#1e2d40", "accent": "#00c8ff", "accent2":"#0057ff",
    "green":  "#00e676", "danger": "#ff3c5a", "warn":   "#ffab40",
    "text":   "#c8d8e8", "muted":  "#4a6070", "white":  "#ffffff",
}
MONO  = ("Consolas", 9)
MONO2 = ("Consolas", 10)
SUI   = ("Segoe UI", 9)
SUI_B = ("Segoe UI", 9, "bold")
SUI_H = ("Segoe UI", 11, "bold")

LOG_Q: queue.Queue = queue.Queue()

# ── Log interceptor ────────────────────────────────────────────────────────────
def _setup_log_intercept():
    import logging

    class GuiHandler(logging.Handler):
        def emit(self, record):
            try:
                msg = self.format(record)
                try:
                    d = json.loads(msg.split("|")[-1].strip())
                    src = d.get("service", "SYS")
                    text = json.dumps({k: v for k, v in d.items()
                                       if k not in ("service",)},
                                      separators=(", ", ":"))
                    LOG_Q.put((src, text))
                except Exception:
                    LOG_Q.put(("SYS", msg))
            except Exception:
                pass

    fmt = logging.Formatter("%(message)s")
    for name in ("HTTP_Honeypot", "FTP_Honeypot", "SSH_Honeypot"):
        h = GuiHandler()
        h.setFormatter(fmt)
        logging.getLogger(name).addHandler(h)


# ── Service card ──────────────────────────────────────────────────────────────
class ServiceCard(tk.Frame):
    def __init__(self, parent, name, icon, default_port,
                 start_fn, stop_fn, **kw):
        super().__init__(parent, bg=C["panel"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        self.name     = name
        self.start_fn = start_fn
        self.stop_fn  = stop_fn
        self.running  = False
        self._build(icon, default_port)

    def _build(self, icon, default_port):
        hdr = tk.Frame(self, bg=C["panel"])
        hdr.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(hdr, text=icon, font=("Segoe UI Emoji", 16),
                 bg=C["panel"], fg=C["accent"]).pack(side="left")
        tk.Label(hdr, text=f"  {self.name}",
                 font=SUI_H, bg=C["panel"], fg=C["white"]).pack(side="left")
        self.status_v = tk.StringVar(value="● OFF")
        self.status_l = tk.Label(hdr, textvariable=self.status_v,
                                  font=MONO, bg=C["panel"], fg=C["muted"])
        self.status_l.pack(side="right")

        prow = tk.Frame(self, bg=C["panel"])
        prow.pack(fill="x", padx=14, pady=(0, 8))
        tk.Label(prow, text="PORT:", font=SUI, bg=C["panel"],
                 fg=C["muted"]).pack(side="left")
        self.port_v = tk.StringVar(value=str(default_port))
        tk.Entry(prow, textvariable=self.port_v, width=6, font=MONO2,
                 bg="#0a0c10", fg=C["accent"],
                 insertbackground=C["accent"], relief="flat",
                 highlightbackground=C["border"],
                 highlightthickness=1).pack(side="left", padx=(6, 0))

        brow = tk.Frame(self, bg=C["panel"])
        brow.pack(fill="x", padx=14, pady=(0, 12))
        self.sb = tk.Button(brow, text="▶ START", font=SUI_B,
                             bg=C["accent2"], fg=C["white"],
                             relief="flat", cursor="hand2",
                             padx=12, pady=5, command=self._start)
        self.sb.pack(side="left", padx=(0, 6))
        self.xb = tk.Button(brow, text="■ STOP", font=SUI_B,
                             bg=C["border"], fg=C["muted"],
                             relief="flat", cursor="hand2",
                             padx=12, pady=5, state="disabled",
                             command=self._stop)
        self.xb.pack(side="left")

    def _start(self):
        try:
            port = int(self.port_v.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Port",
                                  f"Enter a valid port for {self.name}.")
            return
        try:
            self.start_fn(port)
            self.running = True
            self.status_v.set("● LIVE")
            self.status_l.config(fg=C["green"])
            self.sb.config(state="disabled", bg=C["border"], fg=C["muted"])
            self.xb.config(state="normal", bg=C["danger"], fg=C["white"])
            LOG_Q.put((self.name, f"Started on port {port}"))
        except PermissionError:
            messagebox.showerror("Permission",
                                  f"Port {port} needs root/admin.")
        except OSError as e:
            messagebox.showerror("Error", str(e))

    def _stop(self):
        self.stop_fn()
        self.running = False
        self.status_v.set("● OFF")
        self.status_l.config(fg=C["muted"])
        self.sb.config(state="normal", bg=C["accent2"], fg=C["white"])
        self.xb.config(state="disabled", bg=C["border"], fg=C["muted"])
        LOG_Q.put((self.name, "Stopped"))


# ── Stats label helper ────────────────────────────────────────────────────────
def _stat_row(parent, label, var):
    f = tk.Frame(parent, bg=C["panel2"])
    f.pack(fill="x", pady=1)
    tk.Label(f, text=label, font=SUI, bg=C["panel2"],
             fg=C["muted"], width=20, anchor="w").pack(side="left")
    tk.Label(f, textvariable=var, font=MONO2,
             bg=C["panel2"], fg=C["accent"]).pack(side="left")


# ── Main app ──────────────────────────────────────────────────────────────────
class HoneypotApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🍯 Honeypot Suite — Laxmi Chit Fund Honeypot Lab")
        self.root.configure(bg=C["bg"])
        self.root.minsize(1000, 700)
        self._evt_count   = 0
        self._alert_count = 0

        self._build()
        self._setup_log_intercept()
        self._poll_logs()
        self._poll_stats()
        self._update_clock()

    def _setup_log_intercept(self):
        _setup_log_intercept()
        # Register GUI alert callback
        alerts.register_gui_callback(self._on_alert)
        LOG_Q.put(("SYS", "Honeypot Suite ready. Configure ports and START services."))
        LOG_Q.put(("SYS", "Logs → ./logs/   Attack files → ./attacks/   Exports → ./exports/"))

    # ── UI build ──────────────────────────────────────────────────────────────
    def _build(self):
        # Top bar
        tb = tk.Frame(self.root, bg="#060810", height=50)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        tk.Label(tb, text="🍯  HONEYPOT SUITE",
                 font=("Segoe UI", 13, "bold"),
                 bg="#060810", fg=C["white"]).pack(side="left", padx=16)
        tk.Label(tb, text="LAXMI CHIT FUND HONEYPOT LAB",
                 font=SUI, bg="#060810", fg=C["muted"]).pack(side="left")
        self.clock_v = tk.StringVar()
        tk.Label(tb, textvariable=self.clock_v,
                 font=MONO, bg="#060810", fg=C["accent"]).pack(side="right", padx=16)

        # ── Service cards row ──────────────────────────────────────────────────
        cf = tk.Frame(self.root, bg=C["bg"])
        cf.pack(fill="x", padx=14, pady=(12, 0))

        self.http_card = ServiceCard(cf, "HTTP", "🌐", 8080,
                                      http_honeypot.start, http_honeypot.stop)
        self.http_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.ftp_card = ServiceCard(cf, "FTP", "📁", 2121,
                                     ftp_honeypot.start, ftp_honeypot.stop)
        self.ftp_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.ssh_card = ServiceCard(cf, "SSH", "🔒", 2222,
                                     ssh_honeypot.start, ssh_honeypot.stop)
        self.ssh_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        # Decoy services card
        decoy_frame = tk.Frame(cf, bg=C["panel"],
                               highlightbackground=C["border"],
                               highlightthickness=1)
        decoy_frame.pack(side="left", fill="both", expand=True)
        # Docker status indicator
        docker_frame = tk.Frame(cf, bg=C["panel"],
                                highlightbackground=C["border"],
                                highlightthickness=1)
        docker_frame.pack(side="left", fill="both", expand=True, padx=(0,6))
        tk.Label(docker_frame, text="🐳  DOCKER SANDBOX",
                 font=SUI_H, bg=C["panel"], fg="#00c8ff").pack(
                 padx=14, pady=(12,4), anchor="w")
        self.docker_status_v = tk.StringVar(value="Checking...")
        tk.Label(docker_frame, textvariable=self.docker_status_v,
                 font=MONO, bg=C["panel"],
                 fg=C["muted"], justify="left").pack(
                 padx=14, pady=(0,8), anchor="w")
        self.root.after(1000, self._update_docker_status)

        tk.Label(decoy_frame, text="🔌  DECOY SERVICES",
                 font=SUI_H, bg=C["panel"], fg=C["warn"]).pack(padx=14, pady=(12, 4), anchor="w")
        tk.Label(decoy_frame,
                 text="MySQL:3306  Redis:6379\nSMTP:2525   DNS:5353\nHTTPS:4443  ES:9200\nAdmin:8081",
                 font=MONO, bg=C["panel"], fg=C["muted"],
                 justify="left").pack(padx=14, pady=(0, 8), anchor="w")
        brow = tk.Frame(decoy_frame, bg=C["panel"])
        brow.pack(padx=14, pady=(0, 12), anchor="w")
        self.decoy_v = tk.StringVar(value="● OFF")
        self.decoy_status = tk.Label(brow, textvariable=self.decoy_v,
                                      font=MONO, bg=C["panel"], fg=C["muted"])
        self.decoy_status.pack(side="left", padx=(0, 8))
        self.decoy_sb = tk.Button(brow, text="▶ START", font=SUI_B,
                                   bg=C["accent2"], fg=C["white"],
                                   relief="flat", padx=10, pady=4,
                                   command=self._start_decoy)
        self.decoy_sb.pack(side="left")

        # ── Control bar ────────────────────────────────────────────────────────
        ctrl = tk.Frame(self.root, bg=C["bg"])
        ctrl.pack(fill="x", padx=14, pady=8)
        for txt, bg, cmd in [
            ("▶▶ START ALL", C["green"],  self._start_all),
            ("■■ STOP ALL",  C["danger"], self._stop_all),
            ("📤 Export JSON", "#1e3250", self._export_json),
            ("📊 Export CSV",  "#1e3250", self._export_csv),
            ("📄 PDF Report",  "#1e3250", self._gen_report),
            ("⚙ Notifier",     "#1e3250", self._open_notifier),
            ("🗑 Clear Logs",  "#1e3250", self._clear_logs),
            ("📊 Analytics",   C["accent2"], self._open_analytics),
            ("📋 Logs Table",  "#1e3250", self._open_log_viewer),
            ("🎯 MITRE Map",   "#1e3250", self._open_mitre_view),
            ("🦠 Malware",     "#1e3250", self._open_malware_view),
        ]:
            fg = "#000" if bg == C["green"] else C["white"]
            tk.Button(ctrl, text=txt, font=SUI_B, bg=bg, fg=fg,
                      relief="flat", padx=14, pady=6, cursor="hand2",
                      command=cmd).pack(side="left", padx=(0, 6))

        tk.Label(ctrl, text="📂 logs/  attacks/  exports/",
                 font=SUI, bg=C["bg"], fg=C["muted"]).pack(side="right")

        # ── Main content: stats left, log right ────────────────────────────────
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Stats panel
        sp = tk.Frame(main, bg=C["panel2"], width=270,
                      highlightbackground=C["border"], highlightthickness=1)
        sp.pack(side="left", fill="y", padx=(0, 8))
        sp.pack_propagate(False)

        tk.Label(sp, text=" 📊  ATTACKER STATS",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["accent"]).pack(fill="x", padx=8, pady=8)

        # KPI metrics
        kpi = tk.Frame(sp, bg=C["panel2"])
        kpi.pack(fill="x", padx=8, pady=(0, 8))

        self.total_v    = tk.StringVar(value="0")
        self.active_v   = tk.StringVar(value="0")
        self.scanner_v  = tk.StringVar(value="0")
        for lbl, var in [
            ("Total Connections:", self.total_v),
            ("Active Sessions:",   self.active_v),
            ("Scanners Detected:", self.scanner_v),
        ]:
            _stat_row(kpi, lbl, var)

        # Separator
        tk.Frame(sp, bg=C["border"], height=1).pack(fill="x", padx=4)

        # Top IPs
        tk.Label(sp, text=" Top Attacker IPs",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["warn"]).pack(anchor="w", padx=8, pady=(8, 2))
        self.ips_box = tk.Text(sp, height=5, bg="#0a0c10",
                                fg=C["text"], font=MONO,
                                relief="flat", state="disabled")
        self.ips_box.pack(fill="x", padx=8, pady=(0, 6))

        # Top passwords
        tk.Label(sp, text=" Top Passwords",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["danger"]).pack(anchor="w", padx=8, pady=(4, 2))
        self.pwd_box = tk.Text(sp, height=4, bg="#0a0c10",
                                fg=C["text"], font=MONO,
                                relief="flat", state="disabled")
        self.pwd_box.pack(fill="x", padx=8, pady=(0, 4))

        # Top usernames
        tk.Label(sp, text=" Top Usernames",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["warn"]).pack(anchor="w", padx=8, pady=(4, 2))
        self.uname_box = tk.Text(sp, height=4, bg="#0a0c10",
                                  fg=C["text"], font=MONO,
                                  relief="flat", state="disabled")
        self.uname_box.pack(fill="x", padx=8, pady=(0, 4))

        # Top commands
        tk.Label(sp, text=" Top Commands (SSH)",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["accent"]).pack(anchor="w", padx=8, pady=(4, 2))
        self.cmd_box = tk.Text(sp, height=5, bg="#0a0c10",
                                fg=C["text"], font=MONO,
                                relief="flat", state="disabled")
        self.cmd_box.pack(fill="x", padx=8, pady=(0, 6))

        # Top countries
        tk.Label(sp, text=" Top Countries",
                 font=SUI_B, bg=C["panel2"],
                 fg=C["green"]).pack(anchor="w", padx=8, pady=(4, 2))
        self.country_box = tk.Text(sp, height=4, bg="#0a0c10",
                                    fg=C["text"], font=MONO,
                                    relief="flat", state="disabled")
        self.country_box.pack(fill="x", padx=8, pady=(0, 8))

        # Log panel
        lp = tk.Frame(main, bg=C["bg"])
        lp.pack(side="left", fill="both", expand=True)

        lhdr = tk.Frame(lp, bg=C["panel"],
                        highlightbackground=C["border"],
                        highlightthickness=1)
        lhdr.pack(fill="x")
        tk.Label(lhdr, text=" 📋  LIVE EVENT LOG",
                 font=SUI_B, bg=C["panel"],
                 fg=C["accent"]).pack(side="left", pady=6, padx=4)
        self.evt_v = tk.StringVar(value="0 events")
        tk.Label(lhdr, textvariable=self.evt_v,
                 font=MONO, bg=C["panel"],
                 fg=C["muted"]).pack(side="right", padx=10)

        self.log_box = scrolledtext.ScrolledText(
            lp, bg="#060810", fg=C["text"], font=MONO,
            relief="flat", state="disabled", wrap="word"
        )
        self.log_box.pack(fill="both", expand=True)

        # ── Notebook: Alerts + Sessions tabs ──────────────────────────────────
        nb = ttk.Notebook(lp)
        # Patch ttk notebook style
        nb.pack(fill="x", pady=(6, 0))

        # Alerts tab
        af = tk.Frame(nb, bg=C["bg"])
        nb.add(af, text="  🚨 ALERTS  ")

        alert_hdr = tk.Frame(af, bg=C["panel"],
                              highlightbackground=C["border"], highlightthickness=1)
        alert_hdr.pack(fill="x")
        tk.Label(alert_hdr, text=" 🚨  LIVE ALERTS",
                 font=SUI_B, bg=C["panel"], fg=C["danger"],
                 pady=5).pack(side="left", padx=4)
        self.alert_count_v = tk.StringVar(value="0 alerts")
        tk.Label(alert_hdr, textvariable=self.alert_count_v,
                 font=MONO, bg=C["panel"], fg=C["danger"]).pack(side="right", padx=10)

        self.alert_box = scrolledtext.ScrolledText(
            af, bg="#0a0010", fg=C["text"], font=MONO,
            relief="flat", state="disabled", wrap="word", height=8
        )
        self.alert_box.pack(fill="both", expand=True)
        for sev, col in [("CRITICAL","#cc0000"),("HIGH","#ff3c5a"),
                          ("MEDIUM","#ff8c00"),("LOW","#ffab40"),
                          ("ts","#4a6070"),("label","#ffffff")]:
            self.alert_box.tag_config(sev, foreground=col)

        # Sessions tab
        sf = tk.Frame(nb, bg=C["bg"])
        nb.add(sf, text="  📹 SESSIONS  ")

        # Attack map tab
        mf = tk.Frame(nb, bg=C["bg"])
        nb.add(mf, text="  🌍 ATTACK MAP  ")
        self.attack_map = amap.AttackMapWidget(
            mf, width=860, height=280
        )
        self.attack_map.pack(fill="both", expand=True, padx=4, pady=4)

        sess_hdr = tk.Frame(sf, bg=C["panel"],
                             highlightbackground=C["border"], highlightthickness=1)
        sess_hdr.pack(fill="x")
        tk.Label(sess_hdr, text=" 📹  RECORDED SESSIONS",
                 font=SUI_B, bg=C["panel"], fg=C["accent"],
                 pady=5).pack(side="left", padx=4)
        tk.Button(sess_hdr, text="🔄 Refresh",
                  font=SUI, bg=C["border"], fg=C["text"],
                  relief="flat", padx=8, pady=3,
                  command=self._refresh_sessions).pack(side="right", padx=6)

        self.session_box = scrolledtext.ScrolledText(
            sf, bg="#060810", fg=C["text"], font=MONO,
            relief="flat", state="disabled", wrap="word", height=8
        )
        self.session_box.pack(fill="both", expand=True)
        self.session_box.tag_config("header", foreground=C["accent"])
        self.session_box.tag_config("path",   foreground=C["warn"])
        self.session_box.tag_config("ts",     foreground=C["muted"])

        for tag, color in [("HTTP","#00c8ff"),("FTP","#ffab40"),
                            ("SSH","#c792ea"),("SYS","#00e676"),
                            ("MYSQL","#ff8c00"),("REDIS","#ff4136"),
                            ("SMTP","#7fdbff"),("DNS","#39ff14"),
                            ("ES","#f0a500"),("HTTPS","#00bfff"),
                            ("ADMIN","#da70d6"),("ts","#4a6070")]:
            self.log_box.tag_config(tag, foreground=color)

        # Status bar
        sb2 = tk.Frame(self.root, bg="#060810", height=22)
        sb2.pack(fill="x", side="bottom")
        sb2.pack_propagate(False)
        tk.Label(sb2,
                 text=" ⚠  Authorized research & education use only  ·  Laxmi Chit Fund Honeypot Lab",
                 font=("Segoe UI", 8), bg="#060810",
                 fg=C["muted"]).pack(side="left", padx=8)

    # ── Decoy control ─────────────────────────────────────────────────────────
    def _start_decoy(self):
        try:
            decoy_services.start(mysql_port=3306, redis_port=6379, smtp_port=2525,
                              dns_port=5353, https_port=4443, admin_port=8081, es_port=9200)
            self.decoy_v.set("● LIVE")
            self.decoy_status.config(fg=C["green"])
            self.decoy_sb.config(state="disabled",
                                  bg=C["border"], fg=C["muted"])
            LOG_Q.put(("SYS", "Decoy services started: MySQL:3306 Redis:6379 SMTP:2525"))
        except Exception as e:
            messagebox.showerror("Decoy Error", str(e))

    # ── Global controls ───────────────────────────────────────────────────────
    def _start_all(self):
        self.http_card._start()
        self.ftp_card._start()
        self.ssh_card._start()
        self._start_decoy()

    def _stop_all(self):
        self.http_card._stop()
        self.ftp_card._stop()
        self.ssh_card._stop()
        decoy_services.stop()
        self.decoy_v.set("● OFF")
        self.decoy_status.config(fg=C["muted"])

    def _export_json(self):
        path = hp_log.export_json()
        LOG_Q.put(("SYS", f"JSON exported → {path}"))
        messagebox.showinfo("Export", f"Saved to {path}")

    def _export_csv(self):
        path = hp_log.export_csv()
        LOG_Q.put(("SYS", f"CSV exported → {path}"))
        messagebox.showinfo("Export", f"Saved to {path}")

    def _clear_logs(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")
        self._evt_count = 0
        self.evt_v.set("0 events")

    # ── Clock ──────────────────────────────────────────────────────────────────
    def _update_clock(self):
        self.clock_v.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._update_clock)

    # ── Log polling ────────────────────────────────────────────────────────────
    def _poll_logs(self):
        try:
            while True:
                src, msg = LOG_Q.get_nowait()
                self._evt_count += 1
                self.evt_v.set(f"{self._evt_count} events")
                self.log_box.config(state="normal")
                ts = datetime.now().strftime("%H:%M:%S")
                tag = src if src in ("HTTP","FTP","SSH","SYS",
                                      "MYSQL","REDIS","SMTP") else "SYS"
                self.log_box.insert("end", f"[{ts}] ", "ts")
                self.log_box.insert("end", f"[{src:<6}] ", tag)
                self.log_box.insert("end", msg + "\n")
                self.log_box.see("end")
                self.log_box.config(state="disabled")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_logs)

    # ── Stats polling ──────────────────────────────────────────────────────────
    def _poll_stats(self):
        try:
            a = hp_log.get_analytics()
            self.total_v.set(str(a["total_connections"]))
            self.active_v.set(str(a["active_sessions"]))
            self.scanner_v.set(str(sum(a["scanners"].values())))

            def _fill(box, items, fmt="{k:<20} {v}"):
                box.config(state="normal")
                box.delete("1.0", "end")
                for k, v in items[:5]:
                    box.insert("end", fmt.format(k=str(k)[:18], v=v) + "\n")
                box.config(state="disabled")

            _fill(self.ips_box,      a["top_ips"])
            _fill(self.pwd_box,      a["top_passwords"])
            _fill(self.uname_box,    a["top_usernames"])
            _fill(self.cmd_box,      a["top_commands"])
            _fill(self.country_box,  a["countries"])
            # Update attack map
            try:
                self.attack_map.update_attacks(a)
            except Exception:
                pass
        except Exception:
            pass
        self.root.after(3000, self._poll_stats)

    def _on_alert(self, alert: dict):
        """Called from alert_system (background thread) — use after() to update GUI."""
        try:
            self.root.after(0, self._display_alert, alert)
        except Exception:
            pass

    def _display_alert(self, alert: dict):
        # Add dot to attack map
        try:
            self.attack_map.add_attack(
                alert.get('ip','127.0.0.1'),
                alert.get('severity','MEDIUM')
            )
        except Exception:
            pass
        self._alert_count += 1
        self.alert_count_v.set(f"{self._alert_count} alerts")
        sev  = alert.get('severity', 'MEDIUM')
        atype = alert.get('type', '?')
        ip   = alert.get('ip', '?')
        detail = alert.get('detail', '')
        ts   = datetime.now().strftime('%H:%M:%S')
        emoji_map = {'CRITICAL':'🚨','HIGH':'🔴','MEDIUM':'🟡','LOW':'🔵'}
        emoji = emoji_map.get(sev, '⚪')

        self.alert_box.config(state='normal')
        self.alert_box.insert('end', f'[{ts}] ', 'ts')
        self.alert_box.insert('end', f'{emoji} [{sev}] ', sev)
        self.alert_box.insert('end', f'[{atype}] ', 'label')
        self.alert_box.insert('end', f'IP:{ip}  {detail}\n')
        self.alert_box.see('end')
        self.alert_box.config(state='disabled')

        # Flash title bar
        orig = self.root.title()
        self.root.title(f'🚨 ALERT: {atype} from {ip}')
        self.root.after(3000, lambda: self.root.title(orig))

        # Also push to main log
        LOG_Q.put(('SYS', f'ALERT [{sev}] {atype} | {ip} | {detail}'))

        # Try system bell
        try:
            if sev in ('CRITICAL', 'HIGH'):
                self.root.bell()
        except Exception:
            pass

    def _refresh_sessions(self):
        sessions = sr.list_sessions()
        self.session_box.config(state='normal')
        self.session_box.delete('1.0', 'end')
        if not sessions:
            self.session_box.insert('end',
                'No sessions recorded yet. Sessions appear here when attackers connect via SSH.\n')
        else:
            self.session_box.insert('end',
                f"{'File':<52} {'Events':>7} {'Size':>7}  Title\n", 'header')
            self.session_box.insert('end', '─'*100 + '\n', 'ts')
            for s in sessions:
                ts_str = datetime.fromtimestamp(s['timestamp']).strftime('%Y-%m-%d %H:%M') \
                         if s['timestamp'] else '?'
                self.session_box.insert('end', f"{s['file']:<52}", 'path')
                self.session_box.insert('end',
                    f" {s['events']:>7} {s['size_kb']:>5}KB  ", 'ts')
                self.session_box.insert('end', f"{s['title']}\n")
        self.session_box.config(state='disabled')

    def _gen_report(self):
        """Generate PDF report in background thread."""
        def _run():
            try:
                path = rg.generate_report(days=1)
                self.root.after(0, lambda: messagebox.showinfo(
                    'Report Generated',
                    f'PDF report saved:\n{path}'
                ))
                LOG_Q.put(('SYS', f'PDF report generated: {path}'))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    'Report Error', str(e)
                ))
        threading.Thread(target=_run, daemon=True).start()
        LOG_Q.put(('SYS', 'Generating PDF report...'))

    def _open_notifier(self):
        """Open Telegram/Email config window."""
        win = tk.Toplevel(self.root)
        win.title('Notification Settings')
        win.configure(bg=C['bg'])
        win.geometry('520x580')
        win.resizable(False, False)

        cfg = notifier.load_config()
        tg  = cfg.get('telegram', {})
        em  = cfg.get('email', {})

        def lbl(parent, text):
            tk.Label(parent, text=text, font=SUI_B,
                     bg=C['panel2'], fg=C['text'],
                     anchor='w').pack(fill='x', padx=12, pady=(6,2))

        def entry(parent, default='', show=''):
            v = tk.StringVar(value=default)
            tk.Entry(parent, textvariable=v, font=MONO2,
                     bg='#0a0c10', fg=C['accent'],
                     insertbackground=C['accent'],
                     relief='flat',
                     highlightbackground=C['border'],
                     highlightthickness=1,
                     show=show).pack(fill='x', padx=12, pady=(0,4))
            return v

        # ── Telegram section ──
        tf = tk.LabelFrame(win, text='  🤖  Telegram',
                           font=SUI_B, bg=C['panel2'],
                           fg=C['accent'],
                           labelanchor='nw', padx=4, pady=4)
        tf.pack(fill='x', padx=12, pady=(12,6))

        tg_en = tk.BooleanVar(value=tg.get('enabled', False))
        tk.Checkbutton(tf, text='Enable Telegram alerts',
                       variable=tg_en, font=SUI,
                       bg=C['panel2'], fg=C['text'],
                       selectcolor=C['panel']).pack(anchor='w', padx=8)
        lbl(tf, 'Bot Token (from @BotFather):')
        tg_token = entry(tf, tg.get('token', ''))
        lbl(tf, 'Chat ID:')
        tg_chat  = entry(tf, tg.get('chat_id', ''))
        lbl(tf, 'Min Severity:')
        tg_sev = tk.StringVar(value=tg.get('min_severity', 'HIGH'))
        tk.OptionMenu(tf, tg_sev,
                      'LOW','MEDIUM','HIGH','CRITICAL').pack(anchor='w', padx=12)

        def test_tg():
            ok, msg = notifier._test_telegram(
                tg_token.get(), tg_chat.get())
            messagebox.showinfo('Telegram Test',
                                f"{'✅' if ok else '❌'} {msg}")
        tk.Button(tf, text='🧪 Send Test Message',
                  font=SUI_B, bg=C['accent2'], fg=C['white'],
                  relief='flat', padx=10, pady=4,
                  command=test_tg).pack(anchor='w', padx=8, pady=6)

        # ── Email section ──
        ef = tk.LabelFrame(win, text='  📧  Email',
                           font=SUI_B, bg=C['panel2'],
                           fg=C['accent'], labelanchor='nw',
                           padx=4, pady=4)
        ef.pack(fill='x', padx=12, pady=6)

        em_en = tk.BooleanVar(value=em.get('enabled', False))
        tk.Checkbutton(ef, text='Enable Email alerts',
                       variable=em_en, font=SUI,
                       bg=C['panel2'], fg=C['text'],
                       selectcolor=C['panel']).pack(anchor='w', padx=8)
        lbl(ef, 'Gmail (username):')
        em_user = entry(ef, em.get('username', ''))
        lbl(ef, 'App Password:')
        em_pwd  = entry(ef, em.get('password', ''), show='*')
        lbl(ef, 'Send alerts TO:')
        em_to   = entry(ef, em.get('to_addr', ''))

        # ── Save ──
        def save_cfg():
            cfg['telegram'] = {
                'enabled':      tg_en.get(),
                'token':        tg_token.get().strip(),
                'chat_id':      tg_chat.get().strip(),
                'min_severity': tg_sev.get(),
            }
            cfg['email'] = {
                'enabled':      em_en.get(),
                'smtp_host':    'smtp.gmail.com',
                'smtp_port':    587,
                'username':     em_user.get().strip(),
                'password':     em_pwd.get().strip(),
                'from_addr':    em_user.get().strip(),
                'to_addr':      em_to.get().strip(),
                'min_severity': 'HIGH',
            }
            notifier.save_config(cfg)
            LOG_Q.put(('SYS', 'Notifier config saved'))
            messagebox.showinfo('Saved', 'Notification settings saved!')
            win.destroy()

        tk.Button(win, text='💾  Save Settings',
                  font=SUI_B, bg=C['green'], fg='#000',
                  relief='flat', padx=18, pady=8,
                  command=save_cfg).pack(pady=12)

    def _open_analytics(self):
        adash.open_dashboard(self.root)

    def _open_log_viewer(self):
        log_viewer.open_viewer(self.root)

    def _open_mitre_view(self):
        """MITRE ATT&CK mapping viewer window."""
        win = tk.Toplevel(self.root)
        win.title('🎯 MITRE ATT&CK Mappings')
        win.configure(bg=C['bg'])
        win.geometry('1100x620')

        # Header
        hdr = tk.Frame(win, bg=C['panel'],
                       highlightbackground=C['border'], highlightthickness=1)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  🎯  MITRE ATT&CK TECHNIQUE MAPPINGS',
                 font=SUI_B, bg=C['panel'],
                 fg=C['accent'], pady=7).pack(side='left', padx=4)
        tk.Button(hdr, text='🔄 Refresh',
                  font=SUI, bg=C['border'], fg=C['text'],
                  relief='flat', padx=8, pady=3,
                  command=lambda: _refresh_mitre()).pack(side='right', padx=8)

        # Stats bar
        stats_f = tk.Frame(win, bg=C['panel2'])
        stats_f.pack(fill='x', padx=0)
        stats_lbl = tk.Label(stats_f, text='Loading...',
                              font=MONO, bg=C['panel2'], fg=C['muted'])
        stats_lbl.pack(side='left', padx=12, pady=4)

        # Treeview
        style = ttk.Style()
        style.configure('Mitre.Treeview',
                         background=C['panel'], foreground=C['text'],
                         fieldbackground=C['panel'], rowheight=22,
                         font=('Consolas', 9))
        style.configure('Mitre.Treeview.Heading',
                         background=C['bg'], foreground=C['accent'],
                         font=SUI_B, relief='flat')

        cols = ('timestamp','ip','tactic','technique_id',
                'technique','confidence','service')
        vsb = ttk.Scrollbar(win, orient='vertical')
        vsb.pack(side='right', fill='y')
        tree = ttk.Treeview(win, style='Mitre.Treeview',
                             columns=cols, show='headings',
                             yscrollcommand=vsb.set)
        vsb.config(command=tree.yview)
        widths = [140,110,130,80,280,75,65]
        labels = ['Timestamp','IP','Tactic','ID',
                  'Technique','Confidence','Service']
        for col, lbl, w in zip(cols, labels, widths):
            tree.heading(col, text=lbl)
            tree.column(col, width=w, minwidth=40)
        tree.pack(fill='both', expand=True)

        # Color tags
        tree.tag_configure('CRITICAL', foreground='#cc0000')
        tree.tag_configure('HIGH',     foreground='#ff3c5a')
        tree.tag_configure('MEDIUM',   foreground='#ff8c00')
        tree.tag_configure('LOW',      foreground='#ffab40')
        tree.tag_configure('alt',      background='#0d1520')

        TACTIC_COLORS = {
            'Reconnaissance':'#4da3ff', 'Initial Access':'#ff3c5a',
            'Execution':'#ff8c00', 'Persistence':'#cc0000',
            'Privilege Escalation':'#cc0000', 'Discovery':'#ffab40',
            'Collection':'#c792ea', 'Exfiltration':'#ff3c5a',
            'Credential Access':'#ff8c00',
        }
        for tactic, color in TACTIC_COLORS.items():
            tree.tag_configure(f'tac_{tactic.replace(" ","_")}',
                               foreground=color)

        def _refresh_mitre():
            mappings = mitre_attack.load_mappings(500)
            for item in tree.get_children(): tree.delete(item)
            for i, m in enumerate(reversed(mappings)):
                ts  = m.get('timestamp','')[:19].replace('T',' ')
                conf = m.get('confidence','?')
                tac  = m.get('tactic','')
                tag  = conf if conf in ('CRITICAL','HIGH','MEDIUM','LOW') else ''
                ttag = f'tac_{tac.replace(" ","_")}'
                alt  = 'alt' if i%2==1 else ''
                tags = tuple(t for t in [tag, ttag, alt] if t)
                tree.insert('', 'end', values=(
                    ts,
                    m.get('ip',''),
                    tac,
                    m.get('id',''),
                    m.get('technique',''),
                    conf,
                    m.get('service',''),
                ), tags=tags)
            stats = mitre_attack.get_stats()
            top3 = ', '.join(f"{t}({c})" for t,c
                             in stats['by_tactic'][:3])
            stats_lbl.config(
                text=f"Total: {stats['total']}  |  "
                     f"Top tactics: {top3}  |  "
                     f"Techniques: {len(stats['by_technique'])}"
            )

        _refresh_mitre()

    def _open_malware_view(self):
        """Malware capture viewer window."""
        win = tk.Toplevel(self.root)
        win.title('🦠 Malware Capture Log')
        win.configure(bg=C['bg'])
        win.geometry('1050x560')

        hdr = tk.Frame(win, bg=C['panel'],
                       highlightbackground=C['border'], highlightthickness=1)
        hdr.pack(fill='x')
        tk.Label(hdr, text='  🦠  CAPTURED MALWARE SAMPLES',
                 font=SUI_B, bg=C['panel'],
                 fg=C['danger'], pady=7).pack(side='left', padx=4)
        self.mal_count_v = tk.StringVar(value='')
        tk.Label(hdr, textvariable=self.mal_count_v,
                 font=MONO, bg=C['panel'],
                 fg=C['muted']).pack(side='right', padx=12)
        tk.Button(hdr, text='🔄 Refresh',
                  font=SUI, bg=C['border'], fg=C['text'],
                  relief='flat', padx=8, pady=3,
                  command=lambda: _refresh_mal()).pack(side='right', padx=6)

        cols = ('timestamp','ip','service','filename',
                'file_type','size_kb','severity','md5','patterns')
        vsb = ttk.Scrollbar(win, orient='vertical')
        vsb.pack(side='right', fill='y')
        mal_tree = ttk.Treeview(win, style='Mitre.Treeview',
                                 columns=cols, show='headings',
                                 yscrollcommand=vsb.set)
        vsb.config(command=mal_tree.yview)
        for col, lbl, w in zip(cols,
            ['Timestamp','IP','Service','Filename',
             'Type','Size KB','Severity','MD5','Patterns'],
            [140,105,65,140,100,60,70,200,160]):
            mal_tree.heading(col, text=lbl)
            mal_tree.column(col, width=w, minwidth=30)
        mal_tree.pack(fill='both', expand=True)
        for sev, col in [('CRITICAL','#cc0000'),('HIGH','#ff3c5a'),
                          ('MEDIUM','#ff8c00'),('LOW','#ffab40')]:
            mal_tree.tag_configure(sev, foreground=col)

        def _refresh_mal():
            captures = mc.load_captures(200)
            for item in mal_tree.get_children(): mal_tree.delete(item)
            for cap in reversed(captures):
                sev = cap.get('severity','LOW')
                pats = ', '.join(p['pattern'] for p in
                                 cap.get('patterns_found',[])[:2])
                mal_tree.insert('', 'end', tags=(sev,), values=(
                    cap.get('timestamp','')[:19].replace('T',' '),
                    cap.get('ip',''),
                    cap.get('service',''),
                    cap.get('original_name','')[:30],
                    cap.get('file_type',''),
                    cap.get('size_kb',''),
                    sev,
                    cap.get('hashes',{}).get('md5','')[:16],
                    pats[:40] if pats else 'Clean',
                ))
            stats = mc.get_stats()
            self.mal_count_v.set(
                f"Total: {stats['total_files']}  "
                f"Webshells: {stats['webshells']}  "
                f"Executables: {stats['executables']}  "
                f"Known Malware: {stats['known_malware']}"
            )

        _refresh_mal()


    def _update_docker_status(self):
        try:
            if not _DSB_OK:
                self.docker_status_v.set('● NOT INSTALLED\npip install docker')
            elif dsb.is_available():
                active = dsb.get_stats().get('active_containers', 0)
                self.docker_status_v.set(
                    f'● CONNECTED\nImage: ubuntu:22.04\nActive: {active} containers')
            else:
                self.docker_status_v.set(
                    '● UNAVAILABLE\nStart Docker Desktop\nthen restart honeypot')
        except Exception:
            self.docker_status_v.set('● ERROR\nCheck Docker Desktop')
        self.root.after(5000, self._update_docker_status)

    def on_close(self):
        self._stop_all()
        # Cleanup Docker containers
        if _DSB_OK:
            try: dsb.cleanup_all()
            except Exception: pass
        self.root.destroy()


# ── Entry ─────────────────────────────────────────────────────────────────────
def main():
    root = tk.Tk()
    app  = HoneypotApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    w, h = 1100, 780
    x = (root.winfo_screenwidth()  - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.mainloop()

if __name__ == "__main__":
    main()