"""
log_viewer.py — Advanced Log Viewer Window
Opens a separate window with a full sortable/filterable table
of all honeypot events from honeypot_master.log

Features:
  - All columns: timestamp, ip, service, event, username, password,
                 command, payload, country, tool
  - Filter by: service, severity, IP, keyword search
  - Sort by any column (click header)
  - Double-click row → full detail popup
  - Auto-refresh every 5 seconds
  - Export filtered view to CSV
"""

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError:
    class _Stub:
        Toplevel=object; Frame=object; Label=object
        Entry=object; Button=object; Text=object
        Checkbutton=object; Scrollbar=object
        StringVar=object; BooleanVar=object
    tk=_Stub(); ttk=_Stub(); messagebox=_Stub()
import json, os, csv, threading, time
from datetime import datetime

MASTER_LOG = "logs/honeypot_master.log"

# ── Color palette (matches main.py) ──────────────────────────────────────────
C = {
    "bg":     "#0a0c10", "panel":  "#0f1318", "panel2": "#111820",
    "border": "#1e2d40", "accent": "#00c8ff",
    "green":  "#00e676", "danger": "#ff3c5a", "warn":   "#ffab40",
    "text":   "#c8d8e8", "muted":  "#4a6070", "white":  "#ffffff",
}
MONO  = ("Consolas", 9)
SUI   = ("Segoe UI", 9)
SUI_B = ("Segoe UI", 9, "bold")

# Event → row color tag
EVENT_COLORS = {
    "LOGIN_SUCCESS":    "#00e676",
    "LOGIN_FAILURE":    "#ff3c5a",
    "AUTH_FAILURE":     "#ff3c5a",
    "BRUTE_FORCE":      "#ff3c5a",
    "SQLI_ATTEMPT":     "#ff8c00",
    "BAIT_FILE_ACCESS": "#ff8c00",
    "WEBSHELL_UPLOAD":  "#cc0000",
    "MALICIOUS_UPLOAD": "#cc0000",
    "SCANNER_DETECTED": "#ffab40",
    "SSH_COMMAND":      "#4da3ff",
    "RETR_ATTEMPT":     "#c792ea",
    "CONNECT":          "#4a6070",
    "DISCONNECT":       "#4a6070",
}
SERVICE_COLORS = {
    "HTTP":  "#00c8ff",
    "FTP":   "#ffab40",
    "SSH":   "#c792ea",
    "MYSQL": "#ff8c00",
    "REDIS": "#ff4136",
    "SMTP":  "#7fdbff",
    "DNS":   "#39ff14",
    "ES":    "#f0a500",
}

COLUMNS = [
    ("timestamp", "Timestamp",  150),
    ("ip",        "IP Address",  120),
    ("country",   "Country",      90),
    ("service",   "Service",      65),
    ("event",     "Event",       160),
    ("username",  "Username",     90),
    ("password",  "Password",     90),
    ("command",   "Command",     180),
    ("payload",   "Payload",     150),
    ("tool",      "Tool",         80),
]


# ── Load log entries ──────────────────────────────────────────────────────────
def load_entries(limit: int = 2000) -> list[dict]:
    entries = []
    try:
        with open(MASTER_LOG, "r", errors="replace") as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return entries


# ── Main viewer window ────────────────────────────────────────────────────────
class LogViewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("📋 Honeypot Log Viewer")
        self.configure(bg=C["bg"])
        self.geometry("1300x700")
        self.minsize(900, 500)

        self._all_entries  = []
        self._shown        = []
        self._sort_col     = "timestamp"
        self._sort_reverse = True
        self._auto_refresh = True
        self._refresh_job  = None

        self._build()
        self._load_and_render()
        self._schedule_refresh()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build(self):
        # ── Top toolbar ──────────────────────────────────────────────────────
        tb = tk.Frame(self, bg=C["panel"],
                      highlightbackground=C["border"], highlightthickness=1)
        tb.pack(fill="x", padx=0, pady=0)

        tk.Label(tb, text=" 📋  LOG VIEWER",
                 font=SUI_B, bg=C["panel"],
                 fg=C["accent"]).pack(side="left", padx=8, pady=6)

        # Search box
        tk.Label(tb, text="🔍", font=SUI,
                 bg=C["panel"], fg=C["muted"]).pack(side="left")
        self.search_v = tk.StringVar()
        self.search_v.trace_add("write", lambda *_: self._apply_filter())
        tk.Entry(tb, textvariable=self.search_v,
                 width=22, font=MONO,
                 bg="#0a0c10", fg=C["accent"],
                 insertbackground=C["accent"],
                 relief="flat",
                 highlightbackground=C["border"],
                 highlightthickness=1).pack(side="left", padx=(2, 10), ipady=3)

        # Service filter
        tk.Label(tb, text="Service:", font=SUI,
                 bg=C["panel"], fg=C["muted"]).pack(side="left")
        self.svc_v = tk.StringVar(value="ALL")
        svc_menu = ttk.Combobox(tb, textvariable=self.svc_v,
                                 values=["ALL","HTTP","FTP","SSH",
                                         "MYSQL","REDIS","SMTP","DNS","ES"],
                                 width=8, state="readonly", font=SUI)
        svc_menu.pack(side="left", padx=(2, 10))
        svc_menu.bind("<<ComboboxSelected>>", lambda _: self._apply_filter())

        # Event filter
        tk.Label(tb, text="Event:", font=SUI,
                 bg=C["panel"], fg=C["muted"]).pack(side="left")
        self.evt_v = tk.StringVar(value="ALL")
        evt_menu = ttk.Combobox(tb, textvariable=self.evt_v,
                                 values=["ALL",
                                         "LOGIN_SUCCESS","LOGIN_FAILURE",
                                         "AUTH_FAILURE","BRUTE_FORCE",
                                         "SQLI_ATTEMPT","BAIT_FILE_ACCESS",
                                         "WEBSHELL_UPLOAD","SCANNER_DETECTED",
                                         "SSH_COMMAND","RETR_ATTEMPT",
                                         "CONNECT","DISCONNECT"],
                                 width=18, state="readonly", font=SUI)
        evt_menu.pack(side="left", padx=(2, 10))
        evt_menu.bind("<<ComboboxSelected>>", lambda _: self._apply_filter())

        # Buttons
        tk.Button(tb, text="🔄 Refresh",
                  font=SUI_B, bg=C["border"], fg=C["text"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._load_and_render).pack(side="left", padx=(0,4))

        tk.Button(tb, text="📤 Export CSV",
                  font=SUI_B, bg=C["border"], fg=C["text"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._export_csv).pack(side="left", padx=(0,4))

        tk.Button(tb, text="🗑 Clear Filter",
                  font=SUI_B, bg=C["border"], fg=C["text"],
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._clear_filter).pack(side="left", padx=(0,4))

        # Auto refresh toggle
        self.ar_v = tk.BooleanVar(value=True)
        tk.Checkbutton(tb, text="Auto-refresh",
                       variable=self.ar_v, font=SUI,
                       bg=C["panel"], fg=C["muted"],
                       selectcolor=C["bg"],
                       activebackground=C["panel"],
                       command=self._toggle_refresh).pack(side="right", padx=8)

        # Row count
        self.count_v = tk.StringVar(value="0 rows")
        tk.Label(tb, textvariable=self.count_v,
                 font=MONO, bg=C["panel"],
                 fg=C["muted"]).pack(side="right", padx=12)

        # ── Treeview table ────────────────────────────────────────────────────
        frame = tk.Frame(self, bg=C["bg"])
        frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Scrollbars
        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Log.Treeview",
                         background=C["panel"],
                         foreground=C["text"],
                         fieldbackground=C["panel"],
                         rowheight=22,
                         font=MONO)
        style.configure("Log.Treeview.Heading",
                         background=C["bg"],
                         foreground=C["accent"],
                         font=SUI_B,
                         relief="flat")
        style.map("Log.Treeview",
                   background=[("selected", C["accent2"])],
                   foreground=[("selected", C["white"])])

        self.tree = ttk.Treeview(
            frame,
            style="Log.Treeview",
            columns=[c[0] for c in COLUMNS],
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="browse",
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Configure columns + clickable headers for sorting
        for col_id, col_label, col_width in COLUMNS:
            self.tree.heading(col_id, text=col_label,
                              command=lambda c=col_id: self._sort_by(c))
            self.tree.column(col_id, width=col_width,
                              minwidth=40, stretch=False)

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>",   self._on_double_click)

        # Row color tags
        for evt, color in EVENT_COLORS.items():
            self.tree.tag_configure(f"evt_{evt}", foreground=color)
        for svc, color in SERVICE_COLORS.items():
            self.tree.tag_configure(f"svc_{svc}", foreground=color)
        self.tree.tag_configure("alt", background="#0d1520")

        # ── Status bar ────────────────────────────────────────────────────────
        sb = tk.Frame(self, bg="#060810", height=22)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        tk.Label(sb,
                 text=" Double-click row for full details  ·  "
                      "Click column header to sort  ·  "
                      "Auto-refreshes every 5 seconds",
                 font=("Segoe UI", 8), bg="#060810",
                 fg=C["muted"]).pack(side="left", padx=8)

    # ── Data loading ──────────────────────────────────────────────────────────
    def _load_and_render(self):
        self._all_entries = load_entries(2000)
        self._apply_filter()

    def _apply_filter(self):
        kw  = self.search_v.get().lower().strip()
        svc = self.svc_v.get()
        evt = self.evt_v.get()

        filtered = []
        for e in self._all_entries:
            # Service filter
            if svc != "ALL" and e.get("service", "") != svc:
                continue
            # Event filter
            if evt != "ALL" and e.get("event", "") != evt:
                continue
            # Keyword search across all fields
            if kw:
                haystack = " ".join(str(v) for v in e.values()).lower()
                if kw not in haystack:
                    continue
            filtered.append(e)

        # Sort
        rev = self._sort_reverse
        col = self._sort_col
        try:
            filtered.sort(key=lambda x: str(x.get(col, "")), reverse=rev)
        except Exception:
            pass

        self._shown = filtered
        self._render_rows()

    def _render_rows(self):
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)

        for i, e in enumerate(self._shown):
            ts  = e.get("timestamp", "")[:19].replace("T", " ")
            row = (
                ts,
                e.get("ip",       ""),
                e.get("country",  ""),
                e.get("service",  ""),
                e.get("event",    ""),
                e.get("username", ""),
                e.get("password", ""),
                (e.get("command", "") or "")[:60],
                (e.get("payload", "") or "")[:50],
                e.get("tool",     ""),
            )
            evt_tag = f"evt_{e.get('event', '')}"
            alt_tag = "alt" if i % 2 == 1 else ""
            tags = tuple(t for t in [evt_tag, alt_tag] if t)
            self.tree.insert("", "end", iid=str(i), values=row, tags=tags)

        self.count_v.set(f"{len(self._shown):,} rows"
                         f"  (total: {len(self._all_entries):,})")

    # ── Sorting ───────────────────────────────────────────────────────────────
    def _sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col    = col
            self._sort_reverse = True

        # Update header arrow indicator
        for c_id, c_label, _ in COLUMNS:
            arrow = ""
            if c_id == col:
                arrow = " ▼" if self._sort_reverse else " ▲"
            self.tree.heading(c_id, text=c_label + arrow)

        self._apply_filter()

    # ── Double click → detail popup ───────────────────────────────────────────
    def _on_double_click(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx >= len(self._shown):
            return
        entry = self._shown[idx]
        self._show_detail(entry)

    def _show_detail(self, entry: dict):
        win = tk.Toplevel(self)
        win.title(f"Event Detail — {entry.get('event','?')} from {entry.get('ip','?')}")
        win.configure(bg=C["bg"])
        win.geometry("620x480")

        # Header
        svc   = entry.get("service", "?")
        evt   = entry.get("event",   "?")
        color = SERVICE_COLORS.get(svc, C["accent"])
        hdr   = tk.Frame(win, bg=C["panel"],
                          highlightbackground=C["border"],
                          highlightthickness=1)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"  {evt}",
                 font=("Segoe UI", 12, "bold"),
                 bg=C["panel"], fg=color).pack(side="left", pady=8, padx=4)
        tk.Label(hdr, text=f"[{svc}]",
                 font=MONO, bg=C["panel"],
                 fg=C["muted"]).pack(side="left")

        # Scrollable text
        txt = tk.Text(win, bg="#060810", fg=C["text"],
                      font=("Consolas", 10),
                      relief="flat", padx=12, pady=10,
                      wrap="word", state="normal")
        txt.pack(fill="both", expand=True, padx=8, pady=8)

        # Field colors
        txt.tag_config("key",   foreground=C["accent"])
        txt.tag_config("val",   foreground=C["text"])
        txt.tag_config("warn",  foreground=C["warn"])
        txt.tag_config("danger",foreground=C["danger"])
        txt.tag_config("green", foreground=C["green"])

        SENSITIVE = {"password", "payload", "command", "tool"}
        GOOD      = {"LOGIN_SUCCESS", "AUTH_SUCCESS"}
        BAD       = {"LOGIN_FAILURE", "AUTH_FAILURE", "SQLI_ATTEMPT",
                     "WEBSHELL_UPLOAD", "BAIT_FILE_ACCESS", "BRUTE_FORCE"}

        for k, v in sorted(entry.items()):
            txt.insert("end", f"{k:<18}", "key")
            val_str = str(v)
            if k in SENSITIVE and v:
                tag = "danger" if k == "payload" else "warn"
            elif evt in GOOD:
                tag = "green"
            elif evt in BAD:
                tag = "danger"
            else:
                tag = "val"
            txt.insert("end", f"  {val_str}\n", tag)

        txt.config(state="disabled")

        # Copy button
        def copy_all():
            win.clipboard_clear()
            win.clipboard_append(json.dumps(entry, indent=2))
            messagebox.showinfo("Copied", "Event JSON copied to clipboard!")

        tk.Button(win, text="📋 Copy JSON",
                  font=SUI_B, bg=C["border"], fg=C["text"],
                  relief="flat", padx=12, pady=5,
                  command=copy_all).pack(pady=(0, 8))

    # ── Export CSV ────────────────────────────────────────────────────────────
    def _export_csv(self):
        if not self._shown:
            messagebox.showinfo("Export", "No rows to export.")
            return
        os.makedirs("exports", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"exports/filtered_log_{ts}.csv"
        fields = [c[0] for c in COLUMNS]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(self._shown)
        messagebox.showinfo("Exported", f"Saved {len(self._shown)} rows to:\n{path}")

    # ── Clear filters ─────────────────────────────────────────────────────────
    def _clear_filter(self):
        self.search_v.set("")
        self.svc_v.set("ALL")
        self.evt_v.set("ALL")
        self._apply_filter()

    # ── Auto refresh ──────────────────────────────────────────────────────────
    def _schedule_refresh(self):
        if self._auto_refresh:
            self._load_and_render()
        self._refresh_job = self.after(5000, self._schedule_refresh)

    def _toggle_refresh(self):
        self._auto_refresh = self.ar_v.get()

    def destroy(self):
        if self._refresh_job:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
        super().destroy()


# ── Standalone launcher ───────────────────────────────────────────────────────
def open_viewer(parent=None):
    """Open log viewer window. Pass parent tk.Tk() or None."""
    if parent is None:
        root = tk.Tk()
        root.withdraw()
        viewer = LogViewer(root)
        root.mainloop()
    else:
        viewer = LogViewer(parent)
        viewer.focus_force()
        return viewer


if __name__ == "__main__":
    open_viewer()