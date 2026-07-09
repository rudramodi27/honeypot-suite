"""
session_recorder.py — Full Terminal Session Recorder
Records every keystroke + output with precise timestamps.
Saves in asciicast v2 format (compatible with asciinema player).
Also saves plain .log for human reading.
Supports replay via: python session_recorder.py replay <file>
"""

import os, json, time, sys, threading
from datetime import datetime

os.makedirs("sessions", exist_ok=True)


class SessionRecorder:
    """
    Wraps an SSH channel and records:
      - Every byte the attacker types  (event type "i" = input)
      - Every byte the server sends    (event type "o" = output)
      - Precise wall-clock timestamps

    Output files per session:
      sessions/<ip>_<sid>_<ts>.cast   — asciicast v2 (replayable)
      sessions/<ip>_<sid>_<ts>.log    — human-readable plain text
    """

    def __init__(self, ip: str, sid: str, username: str = ""):
        self.ip       = ip
        self.sid      = sid
        self.username = username
        self.start_ts = time.time()
        self._lock    = threading.Lock()
        self._events  = []          # list of [rel_time, type, data]
        self._plain   = []          # list of plain text lines

        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_safe = ip.replace(".", "_")
        base = f"sessions/{ip_safe}_{sid}_{ts_str}"
        self.cast_path = base + ".cast"
        self.log_path  = base + ".log"

        # Write asciicast v2 header
        header = {
            "version": 2,
            "width":   220,
            "height":  50,
            "timestamp": int(self.start_ts),
            "title":   f"Honeypot session | IP: {ip} | User: {username}",
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        with open(self.cast_path, "w") as f:
            f.write(json.dumps(header) + "\n")

        # Write log header
        with open(self.log_path, "w") as f:
            f.write("=" * 70 + "\n")
            f.write(f"Laxmi Chit Fund Honeypot — Session Recording\n")
            f.write(f"IP        : {ip}\n")
            f.write(f"Session ID: {sid}\n")
            f.write(f"Username  : {username}\n")
            f.write(f"Started   : {datetime.now().isoformat()}\n")
            f.write("=" * 70 + "\n\n")

    def record_output(self, data: bytes):
        """Record server → client data (what attacker sees)."""
        text = data.decode(errors="replace")
        rel  = round(time.time() - self.start_ts, 6)
        with self._lock:
            self._events.append([rel, "o", text])
            self._plain.append(("OUTPUT", rel, text))
            self._flush_event([rel, "o", text])

    def record_input(self, data: bytes):
        """Record client → server data (what attacker types)."""
        text = data.decode(errors="replace")
        rel  = round(time.time() - self.start_ts, 6)
        with self._lock:
            self._events.append([rel, "i", text])
            self._plain.append(("INPUT", rel, text))
            self._flush_event([rel, "i", text])
            # Write human-readable input to log
            self._flush_log_input(text, rel)

    def record_command(self, cmd: str):
        """Called when a complete command is submitted."""
        rel = round(time.time() - self.start_ts, 6)
        with self._lock:
            self._plain.append(("CMD", rel, cmd))
            with open(self.log_path, "a") as f:
                f.write(f"[{rel:8.3f}s] $ {cmd}\n")

    def record_event(self, label: str, detail: str = ""):
        """Record a named event (login, file access, disconnect etc.)."""
        rel = round(time.time() - self.start_ts, 6)
        with self._lock:
            with open(self.log_path, "a") as f:
                f.write(f"[{rel:8.3f}s] [{label}] {detail}\n")

    def finish(self):
        """Finalize the session — write summary to log."""
        duration = round(time.time() - self.start_ts, 2)
        cmd_count = sum(1 for t, _, _ in self._plain if t == "CMD")
        with self._lock:
            with open(self.log_path, "a") as f:
                f.write("\n" + "=" * 70 + "\n")
                f.write(f"Session ended  : {datetime.now().isoformat()}\n")
                f.write(f"Duration       : {duration}s\n")
                f.write(f"Commands run   : {cmd_count}\n")
                f.write(f"Replay file    : {self.cast_path}\n")
                f.write("=" * 70 + "\n")
        return {
            "cast_file": self.cast_path,
            "log_file":  self.log_path,
            "duration":  duration,
            "commands":  cmd_count,
        }

    def _flush_event(self, event: list):
        """Append one event line to the .cast file."""
        try:
            with open(self.cast_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    def _flush_log_input(self, text: str, rel: float):
        """Append raw input chars to log (shows keystroke-level detail)."""
        try:
            # Only log printable chars for readability
            printable = "".join(
                c if c.isprintable() or c in ("\r", "\n", "\t") else f"[0x{ord(c):02x}]"
                for c in text
            )
            if printable.strip():
                with open(self.log_path, "a") as f:
                    f.write(f"[{rel:8.3f}s] KEY {repr(printable)}\n")
        except Exception:
            pass


# ── Replay function ────────────────────────────────────────────────────────────
def replay(cast_file: str, speed: float = 1.0, max_wait: float = 3.0):
    """
    Replay a .cast file in the terminal.
    speed  : playback speed multiplier (2.0 = 2x faster)
    max_wait: cap on any single delay (seconds)
    """
    try:
        with open(cast_file) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {cast_file}")
        return

    if not lines:
        return

    # First line is the header
    try:
        header = json.loads(lines[0])
        print(f"\033[1;36m{'='*60}\033[0m")
        print(f"\033[1;36mReplaying: {header.get('title','Session')}\033[0m")
        print(f"\033[1;36mSpeed: {speed}x  |  Max wait: {max_wait}s\033[0m")
        print(f"\033[1;36m{'='*60}\033[0m")
        print("Press Ctrl+C to stop\n")
        time.sleep(1)
    except Exception:
        pass

    prev_ts = 0.0
    try:
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                ts, etype, data = event[0], event[1], event[2]

                # Compute delay
                delay = (ts - prev_ts) / speed
                delay = min(delay, max_wait)
                if delay > 0:
                    time.sleep(delay)
                prev_ts = ts

                if etype == "o":
                    sys.stdout.write(data)
                    sys.stdout.flush()
                # Skip 'i' events — they'd duplicate output
            except (json.JSONDecodeError, IndexError, ValueError):
                continue
    except KeyboardInterrupt:
        print("\n\n\033[1;33m[Replay stopped]\033[0m")

    print(f"\n\n\033[1;32m[Replay complete]\033[0m")


# ── List sessions ──────────────────────────────────────────────────────────────
def list_sessions() -> list[dict]:
    """Return list of recorded sessions with metadata."""
    sessions = []
    if not os.path.exists("sessions"):
        return sessions
    for fname in sorted(os.listdir("sessions"), reverse=True):
        if not fname.endswith(".cast"):
            continue
        path = os.path.join("sessions", fname)
        try:
            with open(path) as f:
                header = json.loads(f.readline())
            log_path = path.replace(".cast", ".log")
            # Count events
            with open(path) as f:
                event_count = sum(1 for _ in f) - 1  # minus header
            sessions.append({
                "file":      path,
                "log":       log_path,
                "title":     header.get("title", fname),
                "timestamp": header.get("timestamp", 0),
                "events":    event_count,
                "size_kb":   round(os.path.getsize(path) / 1024, 1),
            })
        except Exception:
            continue
    return sessions


# ── CLI entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python session_recorder.py replay <file.cast> [speed] [max_wait]")
        print("  python session_recorder.py list")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "list":
        sessions = list_sessions()
        if not sessions:
            print("No sessions recorded yet.")
        else:
            print(f"\n{'File':<50} {'Events':>8} {'Size':>8}  Title")
            print("-" * 100)
            for s in sessions:
                ts = datetime.fromtimestamp(s['timestamp']).strftime("%Y-%m-%d %H:%M")
                print(f"{s['file']:<50} {s['events']:>8} {s['size_kb']:>6}KB  {s['title']}")

    elif cmd == "replay" and len(sys.argv) >= 3:
        cast_file = sys.argv[2]
        speed     = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
        max_wait  = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0
        replay(cast_file, speed, max_wait)

    else:
        print("Unknown command. Use 'replay <file>' or 'list'")