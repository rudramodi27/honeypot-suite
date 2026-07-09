"""
ftp_honeypot.py — Advanced FTP Honeypot
Features: fake filesystem/directories, partial file downloads (bait),
          upload trap, realistic banners, full command logging
"""

import threading, socket, os, random, time
from datetime import datetime
import logger as hp_log
import alert_system as alerts
try:
    import malware_capture as mc
    _MC_OK = True
except ImportError: _MC_OK = False

BANNER = "220 ProFTPD 1.3.7 Server (LCF FTP) [::ffff:172.18.0.1]\r\n"

# ── Fake filesystem ────────────────────────────────────────────────────────────
FS = {
    "/": ["home", "var", "etc", "tmp"],
    "/home": ["admin"],
    "/home/admin": [
        ("users.csv",           182304),
        ("db_backup.sql",       4819200),
        ("password_backup.txt",   2048),
        ("notes.txt",              512),
        (".env",                   384),
        ("database.yml",           512),
        ("config.ini",             420),
        ("deploy_key.pem",        3272),
        ("crontab_backup.txt",     256),
    ],
    "/var": ["backups", "log", "www"],
    "/var/backups": [
        ("lcf_ledger_backup.sql",    52428800),
        ("employee_records_2024.csv", 31457280),
        ("full_backup_2025.tar.gz", 157286400),
        ("backup_2025-03-01.tar.gz", 10485760),
        ("backup_2025-02-01.tar.gz",  9961472),
        ("mysql_dump_full.sql",       5242880),
        ("passwd.bak",                   2408),
        ("shadow.bak",                   1844),
    ],
    "/var/log": [
        ("apache2_access.log", 2097152),
        ("auth.log",           1048576),
        ("syslog",             3145728),
    ],
    "/var/www": ["html"],
    "/var/www/html": [
        ("index.php",   8192),
        ("config.php",  1024),
        ("db.php",      512),
    ],
    "/etc": [
        ("passwd",     2408),
        ("nginx.conf", 4096),
        ("hosts",      312),
        ("crontab",    256),
    ],
    "/tmp": [
        ("session_tmp.dat", 4096),
    ],
}

# ── Partial fake file content (sent during RETR, then cut off) ────────────────
FILE_CONTENT = {
    "users.csv":
        b"id,employee_no,name,email,password_hash,role,branch_code,dept\r\n"
        b"1,LCF-0001,System Admin,admin@laxmichitfund.internal,$2y$10$X9k8.truncated_admin,administrator,HQ,IT\r\n"
        b"2,LCF-1042,Rahul Patel,r.patel@laxmichitfund.internal,$2y$10$Y7m3.truncated_1042,teller,BR-014,Ops\r\n"
        b"3,LCF-1043,Priya Shah,p.shah@laxmichitfund.internal,$2y$10$Z4p1.truncated_1043,teller,BR-014,Ops\r\n"
        b"4,LCF-2005,R.K. Sharma,rk.sharma@laxmichitfund.internal,$2y$10$A3x2.truncated_2005,branch_manager,BR-014,Ops\r\n"
        b"5,LCF-3011,Amit Kumar,a.kumar@laxmichitfund.internal,$2y$10$B8w9.truncated_3011,sysadmin,HQ,IT\r\n",
    "password_backup.txt":
        b"# Password Backup - CONFIDENTIAL\r\n"
        b"# Date: 2025-01-01\r\n"
        b"admin: [see keepass vault - entry: LCF_PROD]\r\n"
        b"mysql_root: [REDACTED - rotate quarterly]\r\n",
    "db_backup.sql":
        b"-- MySQL dump 10.13  Distrib 8.0.32\r\n"
        b"-- Host: localhost    Database: lcf_ledger\r\n"
        b"-- Server version: 8.0.32\r\n"
        b"SET NAMES utf8mb4;\r\n"
        b"CREATE TABLE `users` (\r\n"
        b"  `id` int NOT NULL AUTO_INCREMENT,\r\n"
        b"  `username` varchar(100),\r\n"
        b"  `password_hash` varchar(255),\r\n"
        b"  PRIMARY KEY (`id`)\r\n"
        b") ENGINE=InnoDB;\r\n",
    "config.php":
        b"<?php\r\n"
        b"define('DB_HOST', 'localhost');\r\n"
        b"define('DB_NAME', 'lcf_ledger');\r\n"
        b"define('DB_USER', 'lcf_admin');\r\n"
        b"define('DB_PASS', '***REMOVED***');\r\n"
        b"define('SECRET_KEY', '***REMOVED***');\r\n"
        b"?>\r\n",
    "passwd":
        b"root:x:0:0:root:/root:/bin/bash\r\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
        b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
        b"admin:x:1000:1000:LCF Admin:/home/admin:/bin/bash\r\n",
    ".env":
        b"APP_ENV=production\r\nAPP_DEBUG=false\r\nAPP_URL=https://laxmichitfund.internal\r\n\r\n"
        b"DB_CONNECTION=mysql\r\nDB_HOST=localhost\r\nDB_PORT=3306\r\n"
        b"DB_DATABASE=lcf_ledger\r\nDB_USERNAME=lcf_admin\r\nDB_PASSWORD=***REMOVED***\r\n\r\n"
        b"REDIS_HOST=127.0.0.1\r\nREDIS_PASSWORD=***REMOVED***\r\nREDIS_PORT=6379\r\n\r\n"
        b"JWT_SECRET=***REMOVED***\r\nJWT_EXPIRY=3600\r\n"
        b"AWS_ACCESS_KEY_ID=***REMOVED***\r\nAWS_SECRET_ACCESS_KEY=***REMOVED***\r\n",

    "database.yml":
        b"production:\r\n"
        b"  adapter: mysql2\r\n"
        b"  host: localhost\r\n"
        b"  database: lcf_ledger\r\n"
        b"  username: lcf_admin\r\n"
        b"  password: ***REMOVED***\r\n"
        b"  pool: 10\r\n"
        b"backup:\r\n"
        b"  host: 172.18.0.50\r\n"
        b"  database: lcf_ledger_archive\r\n"
        b"  username: backup_user\r\n"
        b"  password: ***REMOVED***\r\n",

    "config.ini":
        b"[database]\r\nhost=localhost\r\nport=3306\r\n"
        b"name=lcf_ledger\r\nuser=lcf_admin\r\npassword=***REMOVED***\r\n\r\n"
        b"[redis]\r\nhost=127.0.0.1\r\nport=6379\r\npassword=***REMOVED***\r\n\r\n"
        b"[mail]\r\nsmtp_host=mail.laxmichitfund.internal\r\nsmtp_port=587\r\n"
        b"username=noreply@laxmichitfund.internal\r\npassword=***REMOVED***\r\n",

    "lcf_ledger_backup.sql":
        b"-- MySQL dump 10.19  Distrib 8.0.32\r\n"
        b"-- Host: localhost  Database: lcf_ledger\r\n"
        b"-- Dump date: 2025-03-01 03:00:04\r\n"
        b"SET NAMES utf8mb4;\r\n"
        b"CREATE TABLE `users` (\r\n"
        b"  `id` int NOT NULL AUTO_INCREMENT,\r\n"
        b"  `employee_no` varchar(20) NOT NULL,\r\n"
        b"  `password_hash` varchar(255) NOT NULL,\r\n"
        b"  PRIMARY KEY (`id`)\r\n"
        b") ENGINE=InnoDB;\r\n"
        b"INSERT INTO `users` VALUES\r\n"
        b"(1,'admin','$2y$10$TRUNCATED_HASH'),\r\n"
        b"(2,'LCF-1042','$2y$10$TRUNCATED_HASH'),\r\n",

    "employee_records_2024.csv":
        b"employee_no,name,email,branch_code,dept,rating\r\n"
        b"LCF-1042,Rahul Patel,r.patel@laxmichitfund.internal,BR-014,Ops,8.4\r\n"
        b"LCF-1043,Priya Shah,p.shah@laxmichitfund.internal,BR-014,Ops,9.1\r\n"
        b"LCF-3011,Amit Kumar,a.kumar@laxmichitfund.internal,HQ,IT,7.9\r\n"
        b"LCF-3012,Sneha Joshi,s.joshi@laxmichitfund.internal,HQ,IT,8.6\r\n",

    "full_backup_2025.tar.gz":
        b"\x1f\x8b\x08\x00" + bytes(range(16)) +
        b"[BINARY: Full backup archive - password protected]\r\n",

    "nginx.conf":
        b"server {\r\n"
        b"    listen 80;\r\n"
        b"    server_name laxmichitfund.internal www.laxmichitfund.internal;\r\n"
        b"    root /var/www/html;\r\n"
        b"    index index.php index.html;\r\n"
        b"    location ~ \\.php$ {\r\n"
        b"        fastcgi_pass unix:/run/php/php8.0-fpm.sock;\r\n"
        b"    }\r\n"
        b"}\r\n",
}

def _get_content(filename: str) -> bytes:
    return FILE_CONTENT.get(filename, b"[BINARY DATA]\r\n")

def _ls_line(name, size=4096, is_dir=False):
    perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
    return f"{perms}    1 ftp      ftp      {size:>10} Jan 01 00:00 {name}\r\n"

def _dir_listing(path: str) -> str:
    items = FS.get(path, [])
    out = ""
    for item in items:
        if isinstance(item, tuple):
            out += _ls_line(item[0], item[1])
        else:
            out += _ls_line(item, 4096, is_dir=True)
    return out or _ls_line(".", 4096, is_dir=True)

def _file_exists(path: str) -> tuple[bool, int]:
    """Returns (exists, size)"""
    dirname = "/".join(path.split("/")[:-1]) or "/"
    basename = path.split("/")[-1]
    items = FS.get(dirname, [])
    for item in items:
        if isinstance(item, tuple) and item[0] == basename:
            return True, item[1]
    return False, 0


# ── FTP Session ────────────────────────────────────────────────────────────────
class FTPSession(threading.Thread):
    def __init__(self, conn: socket.socket, addr):
        super().__init__(daemon=True)
        self.conn   = conn
        self.ip     = addr[0]
        self.port   = addr[1]
        self.sid    = hp_log.new_session(self.ip, "FTP")
        self.authed = False
        self.user   = None
        self.cwd    = "/"
        self.passive_srv = None
        self.data_host   = self.ip
        self.data_port   = None
        self.mode        = "PORT"
        self.transfer_type = "I"

    def send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode())
        except Exception:
            pass

    def recv(self) -> str:
        buf = b""
        try:
            while True:
                ch = self.conn.recv(1)
                if not ch:
                    break
                buf += ch
                if buf.endswith(b"\n"):
                    break
        except Exception:
            pass
        return buf.decode(errors="replace").strip()

    def _log(self, event, **kw):
        hp_log.log(event, self.ip, "FTP", self.sid,
                   port=21, username=self.user, **kw)

    def _data_conn(self):
        if self.mode == "PASV" and self.passive_srv:
            self.passive_srv.settimeout(8)
            try:
                s, _ = self.passive_srv.accept()
                return s
            except Exception:
                return None
        elif self.mode == "PORT" and self.data_port:
            try:
                s = socket.socket()
                s.settimeout(8)
                s.connect((self.data_host, self.data_port))
                return s
            except Exception:
                return None
        return None

    def _close_pasv(self):
        if self.passive_srv:
            try: self.passive_srv.close()
            except Exception: pass
            self.passive_srv = None

    # ── Command handlers ──────────────────────────────────────────────────────
    def cmd_USER(self, arg):
        self.user = arg
        self._log("USER", command=f"USER {arg}")
        if arg.lower() == "anonymous":
            self.send("331 Anonymous login ok, send email as password.")
        else:
            self.send("331 Password required for " + arg)

    def cmd_PASS(self, arg):
        self._log("PASS", password=arg, command=f"PASS {arg}")
        u = self.user or ""
        if u.lower() == "anonymous" or arg.lower() in ("anonymous", "guest", ""):
            self.authed = True
            self._log("AUTH_SUCCESS_ANON")
            self.send("230 Anonymous login ok.")
        elif u in ("admin", "root", "ftp") and arg == "admin":
            self.authed = True
            self._log("AUTH_SUCCESS")
            self.send("230 Login successful.")
        else:
            self._log("AUTH_FAILURE", password=arg)
            # Give 3 attempts then timeout
            time.sleep(random.uniform(0.5, 1.5))
            self.send("530 Login incorrect.")

    def cmd_SYST(self, _): self.send("215 UNIX Type: L8")
    def cmd_FEAT(self, _): self.send("211-Features:\r\n PASV\r\n SIZE\r\n MDTM\r\n UTF8\r\n211 End")
    def cmd_TYPE(self, a):
        self.transfer_type = a
        self.send(f"200 Type set to {a}.")
    def cmd_NOOP(self, _): self.send("200 NOOP ok.")
    def cmd_ABOR(self, _):
        self._close_pasv()
        self.send("226 ABOR command successful.")

    def cmd_PWD(self, _):
        self.send(f'257 "{self.cwd}" is the current directory.')

    def cmd_CWD(self, arg):
        self._log("CWD", command=f"CWD {arg}")
        if arg == "..":
            parts = self.cwd.rstrip("/").split("/")
            self.cwd = "/".join(parts[:-1]) or "/"
        elif arg.startswith("/"):
            self.cwd = arg.rstrip("/") or "/"
        else:
            self.cwd = (self.cwd.rstrip("/") + "/" + arg)
        self.send(f'250 Directory successfully changed to "{self.cwd}".')

    def cmd_PORT(self, arg):
        try:
            parts = arg.split(",")
            self.data_host = ".".join(parts[:4])
            self.data_port = int(parts[4]) * 256 + int(parts[5])
            self.mode = "PORT"
            self._close_pasv()
            self.send("200 PORT command successful.")
        except Exception:
            self.send("501 Syntax error.")

    def cmd_PASV(self, _):
        self._close_pasv()
        try:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", 0))
            srv.listen(1)
            p = srv.getsockname()[1]
            self.passive_srv = srv
            self.mode = "PASV"
            lip = self.conn.getsockname()[0].replace(".", ",")
            self.send(f"227 Entering Passive Mode ({lip},{p//256},{p%256}).")
        except Exception:
            self.send("425 Cannot open data connection.")

    def cmd_LIST(self, arg):
        if not self.authed:
            self.send("530 Not logged in.")
            return
        self._log("LIST", command=f"LIST {self.cwd}")
        self.send("150 Opening ASCII mode data connection for file list.")
        dc = self._data_conn()
        if dc:
            listing = _dir_listing(self.cwd)
            try:
                dc.sendall(listing.encode())
            except Exception:
                pass
            dc.close()
            self.send("226 Transfer complete.")
        else:
            self.send("425 Cannot open data connection.")

    def cmd_NLST(self, arg): self.cmd_LIST(arg)

    def cmd_RETR(self, arg):
        """Send partial content then drop — makes attackers think data is real."""
        if not self.authed:
            self.send("530 Not logged in.")
            return

        fname = arg.split("/")[-1]
        exists, size = _file_exists(
            self.cwd.rstrip("/") + "/" + fname if not arg.startswith("/") else arg
        )

        self._log("RETR_ATTEMPT", command=f"RETR {arg}", filename=fname)
        alerts.check_ftp_retr(fname, self.ip, self.sid)

        if not exists:
            self.send("550 No such file or directory.")
            return

        content = _get_content(fname)
        # Send only partial content (60-80% of file) then cut
        partial_len = int(len(content) * random.uniform(0.6, 0.8))
        partial = content[:partial_len]

        self.send(f"150 Opening BINARY mode data connection for {fname} ({size} bytes).")
        dc = self._data_conn()
        if dc:
            try:
                dc.sendall(partial)
                time.sleep(random.uniform(0.1, 0.3))
                # Abruptly close — simulates network error
                dc.close()
            except Exception:
                pass
            self._log("RETR_PARTIAL", filename=fname, bytes_sent=partial_len)
            self.send("426 Connection closed; transfer aborted.")
        else:
            self.send("425 Cannot open data connection.")

    def cmd_SIZE(self, arg):
        fname = arg.split("/")[-1]
        _, size = _file_exists(
            self.cwd.rstrip("/") + "/" + fname if not arg.startswith("/") else arg
        )
        self.send(f"213 {size or random.randint(1024, 102400)}")

    def cmd_STOR(self, arg):
        """Accept upload, log, discard."""
        is_malicious = hp_log.detect_malicious_file(arg)
        self._log("STOR_ATTEMPT", filename=arg,
                  command=f"STOR {arg}",
                  is_malicious=is_malicious)
        if is_malicious:
            alerts.check_upload(arg, self.ip, "FTP", self.sid)
        self.send("150 Ok to send data.")
        dc = self._data_conn()
        if dc:
            data = b""
            try:
                while True:
                    chunk = dc.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            dc.close()
            h = __import__("hashlib").sha256(data).hexdigest()
            self._log("STOR_COMPLETE", filename=arg,
                      size=len(data), sha256=h)
            # Malware analysis
            if _MC_OK and data:
                mc.capture(data, arg, self.ip, "FTP", self.sid)
            self.send("226 Transfer complete.")
        else:
            self.send("425 Cannot open data connection.")

    def cmd_DELE(self, arg):
        self._log("DELE_ATTEMPT", command=f"DELE {arg}")
        self.send("550 Permission denied.")

    def cmd_MKD(self, arg):
        self.send("550 Permission denied.")

    def cmd_RMD(self, arg):
        self.send("550 Permission denied.")

    def cmd_QUIT(self, _):
        self._log("QUIT")
        self.send("221 Goodbye.")

    # ── Main loop ─────────────────────────────────────────────────────────────
    def run(self):
        self._log("CONNECT")
        time.sleep(random.uniform(0.1, 0.4))   # realistic banner delay
        self.send(BANNER.strip())
        try:
            while True:
                line = self.recv()
                if not line:
                    break
                parts = line.split(" ", 1)
                cmd   = parts[0].upper()
                arg   = parts[1] if len(parts) > 1 else ""
                # Realistic per-command delay
                time.sleep(random.uniform(0.2, 0.8))
                self._log(f"CMD_{cmd}", command=line[:200])
                handler = getattr(self, f"cmd_{cmd}", None)
                if handler:
                    handler(arg)
                else:
                    self.send(f"502 Command '{cmd}' not implemented.")
        except Exception as e:
            self._log("SESSION_ERROR", command=str(e))
        finally:
            self._close_pasv()
            self.conn.close()
            hp_log.end_session(self.sid)
            self._log("DISCONNECT")


# ── Server ─────────────────────────────────────────────────────────────────────
_srv  = None
_thread = None
_running = False

def _accept(sock):
    while _running:
        try:
            sock.settimeout(1.0)
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            FTPSession(conn, addr).start()
        except Exception:
            pass

def start(port=21):
    global _srv, _thread, _running
    _srv = socket.socket()
    _srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _srv.bind(("0.0.0.0", port))
    _srv.listen(20)
    _running = True
    _thread = threading.Thread(target=_accept, args=(_srv,), daemon=True)
    _thread.start()
    hp_log.log("FTP_START", "0.0.0.0", "FTP", port=port)
    print(f"[FTP Honeypot] Listening on port {port}")

def stop():
    global _running, _srv
    _running = False
    if _srv:
        _srv.close()
    print("[FTP Honeypot] Stopped")