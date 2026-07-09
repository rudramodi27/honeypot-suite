"""
attack_map.py — Live Attacker World Map
Renders a Tkinter canvas world map showing attack origins as pulsing dots.
Uses simple IP-to-region mapping (no external APIs needed).
Updates every 3 seconds from logger analytics.
"""

try:
    import tkinter as tk
    _TK_OK = True
except ImportError:
    _TK_OK = False
    class tk:  # stub
        Frame = object
        Canvas = object
import threading
import time
import random
import math
from datetime import datetime


# ── IP → approximate (lat, lon) mapping ──────────────────────────────────────
# Based on first octet ranges → country clusters
# Each entry: first_octet_range → [(lat, lon, label), ...]
IP_REGIONS = {
    range(1,   10):  [( 37.0,  -95.0, "USA")],
    range(10,  20):  [( 51.5,   -0.1, "UK")],
    range(20,  30):  [( 40.7,  -74.0, "USA")],
    range(30,  50):  [( 48.8,    2.3, "France")],
    range(50,  60):  [( 52.5,   13.4, "Germany")],
    range(60,  70):  [( 55.7,   37.6, "Russia")],
    range(70,  80):  [( 35.6,  139.6, "Japan")],
    range(80,  100): [( 50.0,   14.4, "Czech")],
    range(100, 110): [( 39.9,  116.4, "China")],
    range(110, 120): [( 22.3,  114.2, "Hong Kong")],
    range(120, 130): [( 28.6,   77.2, "India")],
    range(130, 140): [(-23.5,  -46.6, "Brazil")],
    range(140, 150): [( 43.7,  -79.4, "Canada")],
    range(150, 160): [(-33.9,  151.2, "Australia")],
    range(160, 170): [( 59.9,   30.3, "Russia")],
    range(170, 180): [( 37.5,  127.0, "S. Korea")],
    range(180, 190): [( 55.7,   37.6, "Russia")],
    range(190, 200): [(-34.6,  -58.4, "Argentina")],
    range(200, 210): [( 31.2,  121.5, "China")],
    range(210, 220): [(  1.3,  103.8, "Singapore")],
    range(220, 230): [( 13.7,  100.5, "Thailand")],
    range(230, 256): [( 30.0,   31.2, "Egypt")],
}

# Known /8 blocks → precise locations
KNOWN_BLOCKS = {
    "185": ( 55.7,  37.6, "Russia"),
    "198": ( 37.0, -95.0, "USA"),
    "203": (-33.9, 151.2, "Australia"),
    "45":  ( 39.9, 116.4, "China"),
    "91":  ( 55.7,  37.6, "Russia"),
    "46":  ( 52.5,  13.4, "Germany"),
    "5":   ( 51.5,  -0.1, "UK"),
    "89":  ( 48.8,   2.3, "France"),
    "195": ( 50.0,  14.4, "Czech"),
    "77":  ( 41.0,  28.9, "Turkey"),
    "103": ( 22.3, 114.2, "Hong Kong"),
    "104": ( 37.0, -95.0, "USA"),
    "167": (-23.5, -46.6, "Brazil"),
}


def ip_to_latlon(ip: str) -> tuple[float, float, str]:
    """Map IP address to approximate lat/lon + country label."""
    # Private / local
    private_pfx = ("10.", "192.168.", "127.", "172.1", "172.2", "0.")
    for p in private_pfx:
        if ip.startswith(p):
            return 20.5, 78.9, "India (Local)"   # Laxmi Chit Fund HQ is in India

    parts = ip.split(".")
    first = parts[0] if parts else "0"

    # Check known blocks first
    if first in KNOWN_BLOCKS:
        lat, lon, label = KNOWN_BLOCKS[first]
        # Add small jitter so dots don't stack
        lat += random.uniform(-2, 2)
        lon += random.uniform(-2, 2)
        return lat, lon, label

    # Range lookup
    try:
        n = int(first)
        for r, locs in IP_REGIONS.items():
            if n in r:
                lat, lon, label = random.choice(locs)
                lat += random.uniform(-3, 3)
                lon += random.uniform(-3, 3)
                return lat, lon, label
    except ValueError:
        pass

    return 0.0, 0.0, "Unknown"


def latlon_to_canvas(lat: float, lon: float,
                      w: int, h: int) -> tuple[int, int]:
    """Equirectangular projection: lat/lon → canvas pixel."""
    # lon: -180..180 → 0..w
    # lat:  90..-90  → 0..h
    x = int((lon + 180) / 360 * w)
    y = int((90 - lat) / 180 * h)
    return x, y


# ── World map SVG paths (simplified country outlines as pixel polygons) ────────
# We draw a simplified land-mass approximation using filled rectangles/polygons
# This avoids needing any image files.

LAND_RECTS = [
    # (x%, y%, w%, h%, label)  — percentages of canvas size
    # North America
    ( 5, 10, 22, 20, "NA"),
    # South America
    (13, 30, 12, 25, "SA"),
    # Europe
    (42, 10, 10,  15, "EU"),
    # Africa
    (43, 22, 12,  28, "AF"),
    # Russia/Asia
    (48,  5, 35,  20, "RU"),
    # Middle East
    (52, 20,  8,  10, "ME"),
    # South Asia
    (57, 20, 10,  15, "SA2"),
    # Southeast Asia
    (65, 25, 10,  12, "SEA"),
    # East Asia
    (67, 10, 12,  18, "EA"),
    # Australia
    (68, 47, 12,  10, "AU"),
    # Greenland
    (18,  5,  5,   8, "GL"),
    # Japan
    (80, 15,  3,   8, "JP"),
    # UK/Ireland
    (43,  8,  2,   4, "UK"),
    # Scandinavia
    (45,  5,  5,   8, "SC"),
    # Madagascar
    (55, 38,  2,   5, "MG"),
    # New Zealand
    (80, 52,  3,   5, "NZ"),
]


class AttackMapWidget(tk.Frame):
    """
    Embeddable Tkinter widget showing world map with attack dots.
    Call update_attacks(analytics_dict) to refresh the dots.
    """

    DOT_MAX_AGE = 120   # seconds before dot fades out
    PULSE_STEPS = 8

    def __init__(self, parent, width=700, height=340, **kw):
        super().__init__(parent, bg="#0a0c10", **kw)
        self.map_w = width
        self.map_h = height

        self.canvas = tk.Canvas(
            self, width=width, height=height,
            bg="#0a1a2a", highlightthickness=0
        )
        self.canvas.pack(fill="both", expand=True)

        self._attacks: list[dict] = []   # list of {ip, lat, lon, label, ts, color}
        self._pulse_phase = 0
        self._lock = threading.Lock()

        self._draw_map()
        self._animate()

    # ── Draw static map background ─────────────────────────────────────────────
    def _draw_map(self):
        c  = self.canvas
        w  = self.map_w
        h  = self.map_h

        # Ocean background already set via bg

        # Grid lines
        for lon in range(-180, 181, 30):
            x = int((lon + 180) / 360 * w)
            c.create_line(x, 0, x, h, fill="#0d2a40", width=1)
        for lat in range(-90, 91, 30):
            y = int((90 - lat) / 180 * h)
            c.create_line(0, y, w, y, fill="#0d2a40", width=1)

        # Equator highlight
        y_eq = int(90 / 180 * h)
        c.create_line(0, y_eq, w, y_eq, fill="#0e3a54", width=1, dash=(4, 4))

        # Land masses
        for rx, ry, rw, rh, _ in LAND_RECTS:
            x1 = int(rx / 100 * w)
            y1 = int(ry / 100 * h)
            x2 = int((rx + rw) / 100 * w)
            y2 = int((ry + rh) / 100 * h)
            c.create_rectangle(x1, y1, x2, y2,
                                fill="#1a3a28", outline="#1e4a30", width=1)

        # Title
        c.create_text(w // 2, 12, text="LIVE ATTACK MAP",
                      fill="#00c8ff", font=("Consolas", 9, "bold"),
                      anchor="n")

        # Legend
        for i, (label, color) in enumerate([
            ("CRITICAL", "#cc0000"), ("HIGH", "#ff3c5a"),
            ("MEDIUM",   "#ff8c00"), ("LOW",  "#ffab40"),
        ]):
            x = 8 + i * 100
            c.create_oval(x, h-14, x+8, h-6, fill=color, outline="")
            c.create_text(x+12, h-10, text=label,
                          fill="#4a6070", font=("Consolas", 7), anchor="w")

    # ── Add a new attack dot ───────────────────────────────────────────────────
    def add_attack(self, ip: str, severity: str = "MEDIUM",
                   label: str = ""):
        lat, lon, country = ip_to_latlon(ip)
        color_map = {
            "CRITICAL": "#cc0000", "HIGH": "#ff3c5a",
            "MEDIUM":   "#ff8c00", "LOW":  "#ffab40",
        }
        color = color_map.get(severity, "#ffab40")
        display = label or country
        with self._lock:
            self._attacks.append({
                "ip":      ip,
                "lat":     lat,
                "lon":     lon,
                "label":   display,
                "color":   color,
                "severity": severity,
                "ts":      time.time(),
                "canvas_ids": [],
            })
            # Keep max 150 dots
            if len(self._attacks) > 150:
                self._attacks.pop(0)

    def update_attacks(self, analytics: dict):
        """Refresh dots from analytics top_ips list."""
        top_ips = analytics.get("top_ips", [])
        for ip, count in top_ips[:20]:
            # Check if already on map
            with self._lock:
                existing = [a["ip"] for a in self._attacks]
            if ip not in existing:
                sev = "HIGH" if count > 5 else "MEDIUM"
                self.add_attack(ip, sev)

    # ── Animation loop ─────────────────────────────────────────────────────────
    def _animate(self):
        try:
            self._draw_dots()
        except Exception:
            pass
        self._pulse_phase = (self._pulse_phase + 1) % self.PULSE_STEPS
        self.after(400, self._animate)

    def _draw_dots(self):
        c    = self.canvas
        now  = time.time()
        w    = self.canvas.winfo_width()  or self.map_w
        h    = self.canvas.winfo_height() or self.map_h

        # Remove old dot canvas items
        for tag in c.find_withtag("attack_dot"):
            c.delete(tag)
        for tag in c.find_withtag("attack_label"):
            c.delete(tag)
        for tag in c.find_withtag("attack_pulse"):
            c.delete(tag)

        with self._lock:
            attacks = list(self._attacks)

        for atk in attacks:
            age   = now - atk["ts"]
            if age > self.DOT_MAX_AGE:
                continue

            opacity_factor = max(0.2, 1.0 - age / self.DOT_MAX_AGE)
            px, py = latlon_to_canvas(atk["lat"], atk["lon"], w, h)
            color  = atk["color"]

            # Pulsing outer ring — only for recent attacks (< 30s)
            if age < 30:
                pulse_r = 4 + self._pulse_phase * 1.5
                alpha   = max(0, 1.0 - self._pulse_phase / self.PULSE_STEPS)
                c.create_oval(
                    px - pulse_r, py - pulse_r,
                    px + pulse_r, py + pulse_r,
                    outline=color, width=1,
                    tags="attack_pulse"
                )

            # Core dot
            r = 4 if atk["severity"] in ("CRITICAL", "HIGH") else 3
            c.create_oval(px-r, py-r, px+r, py+r,
                          fill=color, outline="#ffffff",
                          width=1 if atk["severity"] == "CRITICAL" else 0,
                          tags="attack_dot")

            # Label (only for recent or critical)
            if age < 45 or atk["severity"] == "CRITICAL":
                c.create_text(px + r + 3, py,
                              text=f"{atk['label']} ({atk['ip']})",
                              fill=color,
                              font=("Consolas", 7),
                              anchor="w",
                              tags="attack_label")

        # Attack count overlay
        c.delete("map_count")
        c.create_text(w - 6, 6,
                      text=f"{len(attacks)} attacks tracked",
                      fill="#4a6070", font=("Consolas", 8),
                      anchor="ne", tags="map_count")