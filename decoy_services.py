"""
decoy_services.py — Extended Fake Banner Services
Covers: MySQL(3306), Redis(6379), SMTP(25), DNS(53),
        HTTPS(443), Admin Panel(8081), ElasticSearch(9200)
Each service: accepts TCP → sends realistic banner → logs payload → closes
"""

import socket, threading, time, random, ssl, os, json, struct
import logger as hp_log

# ─────────────────────────────────────────────────────────────────────────────
# Rotating server banners (anti-fingerprint)
# ─────────────────────────────────────────────────────────────────────────────
MYSQL_BANNERS = [
    "8.0.32", "8.0.33", "8.0.34", "5.7.42", "5.7.43",
]
SMTP_BANNERS = [
    "220 mail.laxmichitfund.internal ESMTP Postfix (Ubuntu)\r\n",
    "220 smtp.laxmichitfund.internal ESMTP Sendmail 8.15.2\r\n",
    "220 mail-relay.laxmichitfund.internal ESMTP ready\r\n",
]
REDIS_BANNERS = [
    "-ERR NOAUTH Authentication required.\r\n",
    "-WRONGPASS invalid username-password pair or user is disabled.\r\n",
]

# ─────────────────────────────────────────────────────────────────────────────
# SMTP conversation
# ─────────────────────────────────────────────────────────────────────────────
SMTP_RESP = {
    "EHLO":  "250-mail.laxmichitfund.internal\r\n250-PIPELINING\r\n250-SIZE 20971520\r\n"
             "250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n"
             "250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
    "HELO":  "250 mail.laxmichitfund.internal\r\n",
    "AUTH":  "535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n",
    "MAIL":  "250 2.1.0 Ok\r\n",
    "RCPT":  "554 5.7.1 Relay access denied\r\n",
    "QUIT":  "221 2.0.0 Bye\r\n",
    "VRFY":  "252 2.0.0 Cannot verify\r\n",
    "NOOP":  "250 2.0.0 Ok\r\n",
    "RSET":  "250 2.0.0 Ok\r\n",
    "DATA":  "354 End data with <CR><LF>.<CR><LF>\r\n",
}

# ─────────────────────────────────────────────────────────────────────────────
# Redis conversation
# ─────────────────────────────────────────────────────────────────────────────
REDIS_RESP = {
    b"PING":         b"+PONG\r\n",
    b"INFO":         b"-ERR NOAUTH Authentication required.\r\n",
    b"KEYS":         b"-ERR NOAUTH Authentication required.\r\n",
    b"CONFIG":       b"-ERR NOAUTH Authentication required.\r\n",
    b"CLIENT":       b"-ERR NOAUTH Authentication required.\r\n",
    b"DBSIZE":       b"-ERR NOAUTH Authentication required.\r\n",
    b"SAVE":         b"-ERR NOAUTH Authentication required.\r\n",
    b"SLAVEOF":      b"-ERR NOAUTH Authentication required.\r\n",
    b"MONITOR":      b"-ERR NOAUTH Authentication required.\r\n",
}

# ─────────────────────────────────────────────────────────────────────────────
# ElasticSearch conversation
# ─────────────────────────────────────────────────────────────────────────────
ES_ROOT = json.dumps({
    "name": "lcf-node-1",
    "cluster_name": "lcf-elastic",
    "cluster_uuid": "xY3kZ9Qp-AbCdEf12345",
    "version": {
        "number": "8.7.1",
        "build_flavor": "default",
        "build_type": "deb",
        "build_hash": "f229ed3f893a515d590d0f39b05f68913e2d9b53",
        "build_date": "2023-04-27T04:33:42.127815583Z",
        "lucene_version": "9.5.0",
        "minimum_wire_compatibility_version": "7.17.0",
        "minimum_index_compatibility_version": "7.0.0"
    },
    "tagline": "You Know, for Search"
})

ES_UNAUTH = json.dumps({
    "error": {
        "root_cause": [{
            "type": "security_exception",
            "reason": "missing authentication credentials for REST request [/]",
            "header": {"WWW-Authenticate": "Basic realm=\"security\" charset=\"UTF-8\""}
        }],
        "type": "security_exception",
        "reason": "missing authentication credentials for REST request [/]"
    },
    "status": 401
})


# ─────────────────────────────────────────────────────────────────────────────
# Generic session handler
# ─────────────────────────────────────────────────────────────────────────────
class DecoySession(threading.Thread):
    def __init__(self, conn, addr, service, port):
        super().__init__(daemon=True)
        self.conn    = conn
        self.ip      = addr[0]
        self.service = service
        self.port    = port

    def _log(self, event, **kw):
        hp_log.log(event, self.ip, self.service, port=self.port, **kw)

    def run(self):
        sid = hp_log.new_session(self.ip, self.service)
        self._log("DECOY_CONNECT")
        # Random realistic delay
        time.sleep(random.uniform(0.1, 0.4))
        try:
            dispatch = {
                "MYSQL": self._mysql,
                "REDIS": self._redis,
                "SMTP":  self._smtp,
                "DNS":   self._dns,
                "HTTPS": self._https,
                "ADMIN": self._admin_panel,
                "ES":    self._elastic,
            }
            handler = dispatch.get(self.service)
            if handler:
                handler(sid)
        except Exception as e:
            self._log("DECOY_ERROR", command=str(e))
        finally:
            try: self.conn.close()
            except Exception: pass
            hp_log.end_session(sid)

    # ── MySQL ──────────────────────────────────────────────────────────────
    def _mysql(self, sid):
        ver = random.choice(MYSQL_BANNERS)
        # Real MySQL handshake greeting packet
        payload = (
            f"\x0a{ver}\x00"
            "\x08\x00\x00\x00"
            "\x52\x7a\x4c\x41\x5e\x55\x39\x58\x00"
            "\xff\xf7\x08\x02\x00\xff\x81\x15"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x60\x59\x4d\x5a\x4c\x38\x52\x30\x35\x5e\x25\x2e\x00"
            "mysql_native_password\x00"
        ).encode(errors="replace")
        pkt_len = len(payload)
        header  = struct.pack("<I", pkt_len)[:3] + b"\x00"
        self.conn.sendall(header + payload)

        self.conn.settimeout(10)
        try:
            data = self.conn.recv(1024)
            if data:
                self._log("MYSQL_HANDSHAKE", payload=data[:80].hex())
        except socket.timeout:
            pass

        # Access denied
        err = b"\x33\x00\x00\x02\xff\x15\x04#28000Access denied for user (using password: YES)\x00"
        self.conn.sendall(err)

    # ── Redis ──────────────────────────────────────────────────────────────
    def _redis(self, sid):
        self.conn.sendall(random.choice(REDIS_BANNERS).encode())
        self.conn.settimeout(30)
        try:
            while True:
                data = self.conn.recv(512)
                if not data:
                    break
                line = data.strip().upper()
                cmd  = line.split(b"\r\n")[0].split(b"\n")[0].strip()
                raw_str = data.decode(errors="replace").strip()
                self._log("REDIS_CMD", command=raw_str[:200])

                if b"AUTH" in cmd:
                    parts = raw_str.split()
                    pwd = parts[-1] if len(parts) > 1 else ""
                    self._log("REDIS_AUTH_ATTEMPT", password=pwd)
                    self.conn.sendall(b"-ERR invalid password\r\n")
                else:
                    base_cmd = cmd.split()[0] if cmd.split() else b""
                    resp = REDIS_RESP.get(base_cmd,
                                          b"-ERR NOAUTH Authentication required.\r\n")
                    self.conn.sendall(resp)
        except socket.timeout:
            pass

    # ── SMTP ───────────────────────────────────────────────────────────────
    def _smtp(self, sid):
        self.conn.sendall(random.choice(SMTP_BANNERS).encode())
        self.conn.settimeout(60)
        try:
            while True:
                data = self.conn.recv(512)
                if not data:
                    break
                line = data.decode(errors="replace").strip()
                self._log("SMTP_CMD", command=line[:200])
                cmd = line.split()[0].upper() if line.split() else ""
                if cmd in ("AUTH", "MAIL FROM", "RCPT TO"):
                    self._log("SMTP_AUTH_ATTEMPT", payload=line)
                resp = SMTP_RESP.get(cmd,
                       "502 5.5.2 Error: command not recognized\r\n")
                self.conn.sendall(resp.encode())
                if cmd == "QUIT":
                    break
        except socket.timeout:
            pass

    # ── DNS (UDP + TCP) ────────────────────────────────────────────────────
    def _dns(self, sid):
        self.conn.settimeout(5)
        try:
            data = self.conn.recv(512)
            if data and len(data) >= 12:
                # Extract query name for logging
                try:
                    offset = 12
                    labels = []
                    while offset < len(data) and data[offset] != 0:
                        length = data[offset]
                        offset += 1
                        labels.append(data[offset:offset+length].decode(errors="replace"))
                        offset += length
                    qname = ".".join(labels)
                except Exception:
                    qname = "unknown"

                self._log("DNS_QUERY", command=f"QUERY {qname}")

                # Build NXDOMAIN response
                resp = data[:2]                   # Transaction ID
                resp += b"\x81\x83"               # Flags: response, NXDOMAIN
                resp += data[4:6]                  # Questions count
                resp += b"\x00\x00\x00\x00\x00\x00"  # Answers/Auth/Additional = 0
                resp += data[12:]                  # Original question section
                self.conn.sendall(resp)
        except Exception:
            pass

    # ── HTTPS (port 443) ───────────────────────────────────────────────────
    def _https(self, sid):
        """Detect TLS ClientHello and return a realistic HTTP/1.1 response."""
        self.conn.settimeout(5)
        try:
            data = self.conn.recv(1024)
            if not data:
                return
            # Check for TLS ClientHello (starts with \x16\x03)
            if data[:2] == b"\x16\x03":
                self._log("TLS_CLIENTHELLO",
                          payload=data[:20].hex())
                # Send TLS Alert: handshake failure — looks like a real server
                # alert = \x15 (Alert) + \x03\x03 (TLS 1.2) + \x00\x02 + \x02\x28
                alert = b"\x15\x03\x03\x00\x02\x02\x28"
                self.conn.sendall(alert)
            else:
                # Plain HTTP on 443 — redirect
                req_line = data.decode(errors="replace").split("\r\n")[0]
                self._log("HTTPS_HTTP_REQUEST", command=req_line[:200])
                resp = (
                    "HTTP/1.1 301 Moved Permanently\r\n"
                    "Location: https://laxmichitfund.internal/\r\n"
                    "Server: nginx/1.24.0\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                )
                self.conn.sendall(resp.encode())
        except Exception:
            pass

    # ── Admin Panel (8081) ──────────────────────────────────────────────────
    def _admin_panel(self, sid):
        """Secondary admin panel — looks like a backup/internal portal."""
        self.conn.settimeout(15)
        try:
            data = self.conn.recv(2048)
            if not data:
                return
            req = data.decode(errors="replace")
            req_line = req.split("\r\n")[0]
            self._log("ADMIN_REQUEST", command=req_line[:200])

            body = (
                "<!DOCTYPE html><html><head><title>Laxmi Chit Fund Internal Portal</title></head>"
                "<body style='font-family:Arial;background:#1a237e;color:#fff;"
                "display:flex;align-items:center;justify-content:center;height:100vh;'>"
                "<div style='text-align:center'>"
                "<h1>Laxmi Chit Fund Internal Management System</h1>"
                "<p>Access restricted to authorized personnel only.</p>"
                "<p><a href='http://localhost:8080/admin' style='color:#ffd166'>"
                "Click here to access the main portal</a></p>"
                "</div></body></html>"
            )
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Server: Apache/2.4.57 (Ubuntu)\r\n"
                f"X-Powered-By: PHP/8.1.12\r\n"
                f"Connection: close\r\n\r\n"
                + body
            )
            self.conn.sendall(resp.encode())
        except Exception:
            pass

    # ── ElasticSearch (9200) ────────────────────────────────────────────────
    def _elastic(self, sid):
        self.conn.settimeout(15)
        try:
            data = self.conn.recv(2048)
            if not data:
                return
            req = data.decode(errors="replace")
            req_line = req.split("\r\n")[0]
            self._log("ES_REQUEST", command=req_line[:200])

            # Check for auth header
            has_auth = "Authorization:" in req
            if has_auth:
                self._log("ES_AUTH_ATTEMPT",
                          payload=req.split("Authorization:")[1].split("\r\n")[0].strip())
                body = ES_UNAUTH
                status = "401 Unauthorized"
            elif "GET / " in req or "GET /\r\n" in req or "HEAD / " in req:
                body = ES_ROOT
                status = "200 OK"
            elif "_cat" in req or "_cluster" in req:
                self._log("ES_RECON", command=req_line)
                body = json.dumps({"error": {"type": "security_exception",
                                              "reason": "missing authentication credentials"}})
                status = "401 Unauthorized"
            else:
                body = ES_UNAUTH
                status = "401 Unauthorized"

            resp = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Type: application/json; charset=UTF-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"X-elastic-product: Elasticsearch\r\n"
                f"X-Powered-By: \r\n"
                f"Connection: close\r\n\r\n"
                + body
            )
            self.conn.sendall(resp.encode())
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# UDP DNS server (port 53)
# ─────────────────────────────────────────────────────────────────────────────
class UDPDNSServer(threading.Thread):
    def __init__(self, port=53):
        super().__init__(daemon=True)
        self.port    = port
        self.running = False
        self.sock    = None

    def stop(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except Exception: pass

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            self.running = True
            hp_log.log("DECOY_DNS_START", "0.0.0.0", "DNS", port=self.port)
            print(f"[Decoy DNS/UDP] Listening on port {self.port}")
            self.sock.settimeout(1.0)
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)
                    if data and len(data) >= 12:
                        # Log query
                        try:
                            offset = 12; labels = []
                            while offset < len(data) and data[offset] != 0:
                                l = data[offset]; offset += 1
                                labels.append(data[offset:offset+l].decode(errors="replace"))
                                offset += l
                            qname = ".".join(labels)
                        except Exception:
                            qname = "unknown"
                        hp_log.log("DNS_QUERY_UDP", addr[0], "DNS",
                                   port=self.port, command=f"QUERY {qname}")
                        # NXDOMAIN response
                        resp = data[:2] + b"\x81\x83" + data[4:6] + \
                               b"\x00\x00\x00\x00\x00\x00" + data[12:]
                        self.sock.sendto(resp, addr)
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except OSError as e:
            print(f"[Decoy DNS/UDP] Cannot bind port {self.port}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Generic TCP decoy server
# ─────────────────────────────────────────────────────────────────────────────
class DecoyServer(threading.Thread):
    def __init__(self, service, port):
        super().__init__(daemon=True)
        self.service = service
        self.port    = port
        self.running = False
        self.sock    = None

    def stop(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except Exception: pass

    def run(self):
        try:
            self.sock = socket.socket()
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.listen(20)
            self.running = True
            hp_log.log(f"DECOY_{self.service}_START",
                       "0.0.0.0", self.service, port=self.port)
            print(f"[Decoy {self.service}] Listening on port {self.port}")
            while self.running:
                self.sock.settimeout(1.0)
                try:
                    conn, addr = self.sock.accept()
                    DecoySession(conn, addr, self.service, self.port).start()
                except socket.timeout:
                    continue
                except Exception:
                    pass
        except OSError as e:
            print(f"[Decoy {self.service}] Cannot bind port {self.port}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
_servers: dict = {}

def start(mysql_port=3306, redis_port=6379, smtp_port=25,
          dns_port=53, https_port=443, admin_port=8081, es_port=9200):
    configs = [
        ("MYSQL", mysql_port),
        ("REDIS", redis_port),
        ("SMTP",  smtp_port),
        ("HTTPS", https_port),
        ("ADMIN", admin_port),
        ("ES",    es_port),
    ]
    for svc, port in configs:
        srv = DecoyServer(svc, port)
        _servers[svc] = srv
        srv.start()

    # UDP DNS
    dns_srv = UDPDNSServer(dns_port)
    _servers["DNS"] = dns_srv
    dns_srv.start()

    # TCP DNS (zone transfers etc.)
    tcp_dns = DecoyServer("DNS", dns_port + 0)  # same port, TCP
    # skip TCP DNS to avoid port conflict with UDP on same port
    # (UDP already handles it)


def stop():
    for srv in _servers.values():
        srv.stop()
    _servers.clear()
    print("[Decoy Services] All stopped")