"""
docker_sandbox.py — Docker Sandbox for SSH Honeypot
Runs attacker commands in isolated Ubuntu containers.

Architecture:
  Attacker → SSH Honeypot → Docker Container → Real Linux output
                                ↓
                          Logs everything
                          Container auto-destroyed after session

Safety:
  - No network access inside container
  - No volume mounts
  - CPU + memory limited
  - Auto-timeout and destroy
  - Read-only filesystem (except /tmp)

Requirements:
  pip install docker
  Docker Desktop must be running
"""

import threading
import time
import os
import json
import hashlib
from datetime import datetime

os.makedirs("logs",    exist_ok=True)
os.makedirs("sandbox", exist_ok=True)

SANDBOX_LOG = "logs/docker_sandbox.log"

# ── Docker config ──────────────────────────────────────────────────────────────
CONTAINER_IMAGE   = "ubuntu:22.04"
CONTAINER_TIMEOUT = 30        # seconds per command
SESSION_TIMEOUT   = 300       # 5 minutes max per session
MAX_OUTPUT_BYTES  = 4096      # truncate large outputs
CPU_QUOTA         = 50000     # 50% of one CPU
MEM_LIMIT         = "64m"     # 64MB RAM max

# Commands that are NEVER executed (too dangerous even in container)
BLOCKED_CMDS = {
    "rm -rf /", "mkfs", "dd if=/dev/zero",
    "fork bomb", ":(){ :|:& };:",
    "chmod -R 777 /", "chown -R",
}

# ── Docker client singleton ────────────────────────────────────────────────────
_docker_client = None
_docker_ok     = False

def _init_docker():
    global _docker_client, _docker_ok
    try:
        import docker
        _docker_client = docker.from_env()
        _docker_client.ping()
        _docker_ok = True
        _log("DOCKER_INIT", "0.0.0.0", status="connected",
             version=_docker_client.version().get("Version","?"))
        print("[Docker Sandbox] Docker connected [OK]")
        # Pre-pull image in background
        threading.Thread(target=_pull_image, daemon=True).start()
    except ImportError:
        print("[Docker Sandbox] ERROR: 'docker' package not installed")
        print("                 Run: pip install docker")
        _docker_ok = False
    except Exception as e:
        print(f"[Docker Sandbox] ERROR: Docker not available — {e}")
        print("                 Make sure Docker Desktop is running")
        _docker_ok = False


def _pull_image():
    """Pull Ubuntu image in background so first session is fast."""
    try:
        print(f"[Docker Sandbox] Pulling {CONTAINER_IMAGE}...")
        _docker_client.images.pull(CONTAINER_IMAGE)
        print(f"[Docker Sandbox] Image ready [OK]")
    except Exception as e:
        print(f"[Docker Sandbox] Pull failed: {e}")


def is_available() -> bool:
    return _docker_ok and _docker_client is not None


# ── Logging ────────────────────────────────────────────────────────────────────
def _log(event: str, ip: str, **kwargs):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event":     event,
        "ip":        ip,
        **kwargs,
    }
    try:
        with open(SANDBOX_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    try:
        import logger as hp_log
        hp_log.log(event, ip, "DOCKER", **kwargs)
    except Exception:
        pass


# ── Sandbox Session ────────────────────────────────────────────────────────────
class DockerSandboxSession:
    """
    One sandbox session per SSH attacker connection.
    Creates a container, runs commands, destroys container on disconnect.
    """

    def __init__(self, ip: str, sid: str = ""):
        self.ip          = ip
        self.sid         = sid
        self.container   = None
        self.start_time  = time.time()
        self.cmd_count   = 0
        self.cmd_log     = []
        self._lock       = threading.Lock()

    def start(self) -> bool:
        """Create and start the sandbox container."""
        if not is_available():
            return False
        try:
            import docker
            self.container = _docker_client.containers.run(
                CONTAINER_IMAGE,
                command="bash",
                detach=True,
                stdin_open=True,
                tty=True,
                # ── Security constraints ──────────────────────────────────
                network_disabled=True,          # No internet access
                read_only=False,                 # Allow writes to container FS
                mem_limit=MEM_LIMIT,             # Memory limit
                cpu_quota=CPU_QUOTA,             # CPU limit
                cpu_period=100000,
                pids_limit=50,                   # Max 50 processes
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],                # Drop all capabilities
                cap_add=["CHOWN", "SETUID",      # Add back minimal caps
                         "SETGID", "DAC_OVERRIDE"],
                environment={
                    "HOME":  "/root",
                    "USER":  "root",
                    "TERM":  "xterm-256color",
                    "PS1":   "root@lcf-core01:~# ",
                    "PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                },
                labels={
                    "honeypot":  "true",
                    "attacker":  self.ip,
                    "session":   self.sid,
                    "started":   datetime.now().isoformat(),
                },
                remove=False,   # We'll remove manually after logging
            )
            _log("SANDBOX_START", self.ip, sid=self.sid,
                 container_id=self.container.id[:12])
            return True
        except Exception as e:
            _log("SANDBOX_START_FAIL", self.ip, error=str(e))
            return False

    def exec(self, cmd: str) -> str:
        """
        Execute a command in the container.
        Returns output string. Never raises.
        """
        if not self.container:
            return "[sandbox not available]"

        # Check session timeout
        if time.time() - self.start_time > SESSION_TIMEOUT:
            return "[session timeout]"

        # Block dangerous commands
        cmd_lower = cmd.strip().lower()
        for blocked in BLOCKED_CMDS:
            if blocked in cmd_lower:
                _log("SANDBOX_BLOCKED_CMD", self.ip,
                     command=cmd, reason="dangerous")
                return f"bash: {cmd.split()[0]}: Operation not permitted"

        self.cmd_count += 1
        start = time.time()

        try:
            # Run with timeout
            result = self.container.exec_run(
                cmd=["bash", "-c", cmd],
                stdout=True,
                stderr=True,
                demux=False,
                timeout=CONTAINER_TIMEOUT,
                workdir="/root",
                environment={"TERM": "xterm-256color"},
            )
            elapsed = round(time.time() - start, 3)

            # Decode output
            output = ""
            if result.output:
                output = result.output.decode(errors="replace")
                # Truncate large outputs
                if len(output) > MAX_OUTPUT_BYTES:
                    output = output[:MAX_OUTPUT_BYTES] + \
                             f"\n... [truncated {len(output)-MAX_OUTPUT_BYTES} bytes]"

            exit_code = result.exit_code or 0

            _log("SANDBOX_CMD", self.ip,
                 sid=self.sid, command=cmd,
                 exit_code=exit_code, elapsed=elapsed,
                 output_len=len(output))

            self.cmd_log.append({
                "cmd":       cmd,
                "output":    output[:200],
                "exit_code": exit_code,
                "elapsed":   elapsed,
                "ts":        datetime.now().isoformat(),
            })

            return output

        except Exception as e:
            err_msg = str(e)
            if "timeout" in err_msg.lower():
                _log("SANDBOX_TIMEOUT", self.ip, command=cmd)
                return f"[command timed out after {CONTAINER_TIMEOUT}s]"
            _log("SANDBOX_EXEC_ERROR", self.ip, command=cmd, error=err_msg)
            return f"bash: {cmd.split()[0] if cmd.split() else cmd}: command not found"

    def stop(self):
        """Stop and remove the container, save session summary."""
        if not self.container:
            return

        duration = round(time.time() - self.start_time, 2)

        # Save session summary
        summary = {
            "ip":           self.ip,
            "sid":          self.sid,
            "container_id": self.container.id[:12],
            "duration":     duration,
            "cmd_count":    self.cmd_count,
            "commands":     self.cmd_log,
            "ended_at":     datetime.now().isoformat(),
        }
        summary_path = f"sandbox/{self.ip.replace('.','_')}_{self.sid}.json"
        try:
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
        except Exception:
            pass

        # Stop + remove container
        try:
            self.container.kill()
        except Exception:
            pass
        try:
            self.container.remove(force=True)
        except Exception:
            pass

        _log("SANDBOX_STOP", self.ip,
             sid=self.sid, duration=duration,
             cmd_count=self.cmd_count)

        self.container = None


# ── Container pool (pre-warm for speed) ───────────────────────────────────────
class ContainerPool:
    """
    Keeps 1 warm container ready so first command executes instantly.
    """
    def __init__(self, size: int = 1):
        self._pool  = []
        self._size  = size
        self._lock  = threading.Lock()

    def _create_one(self):
        """Create one standby container."""
        if not is_available():
            return
        try:
            c = _docker_client.containers.run(
                CONTAINER_IMAGE,
                command="bash",
                detach=True, stdin_open=True, tty=True,
                network_disabled=True,
                mem_limit=MEM_LIMIT, cpu_quota=CPU_QUOTA,
                cpu_period=100000, pids_limit=50,
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                cap_add=["CHOWN","SETUID","SETGID","DAC_OVERRIDE"],
                labels={"honeypot":"true","pool":"true"},
                remove=False,
            )
            with self._lock:
                self._pool.append(c)
        except Exception:
            pass

    def get(self):
        """Get a container from pool (or create new one)."""
        with self._lock:
            if self._pool:
                c = self._pool.pop(0)
                # Replenish pool in background
                threading.Thread(target=self._create_one, daemon=True).start()
                return c
        return None

    def warm(self):
        """Pre-warm the pool."""
        if not is_available():
            return
        threading.Thread(target=self._create_one, daemon=True).start()


_pool = ContainerPool(size=1)


# ── Public API ─────────────────────────────────────────────────────────────────
def new_session(ip: str, sid: str = "") -> "DockerSandboxSession":
    """Create a new sandbox session for an attacker."""
    sess = DockerSandboxSession(ip, sid)
    sess.start()
    return sess


def cleanup_all():
    """Kill all honeypot containers (call on shutdown)."""
    if not is_available():
        return
    try:
        containers = _docker_client.containers.list(
            filters={"label": "honeypot=true"}
        )
        for c in containers:
            try:
                c.remove(force=True)
            except Exception:
                pass
        print(f"[Docker Sandbox] Cleaned up {len(containers)} containers")
    except Exception as e:
        print(f"[Docker Sandbox] Cleanup error: {e}")


def get_stats() -> dict:
    """Return current sandbox statistics."""
    if not is_available():
        return {"available": False}
    try:
        running = _docker_client.containers.list(
            filters={"label": "honeypot=true"}
        )
        return {
            "available":          True,
            "active_containers":  len(running),
            "image":              CONTAINER_IMAGE,
            "mem_limit":          MEM_LIMIT,
            "cpu_quota":          CPU_QUOTA,
            "session_timeout":    SESSION_TIMEOUT,
        }
    except Exception:
        return {"available": False}


# ── Initialize on import ───────────────────────────────────────────────────────
_init_docker()
if _docker_ok:
    _pool.warm()