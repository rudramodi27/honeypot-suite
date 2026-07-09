"""
ssh_honeypot.py — Advanced SSH Honeypot
Features: full filesystem navigation (cd/ls/cat/pwd),
          fake sensitive files, session analytics (duration, typing speed),
          realistic shell prompt, paramiko-based SSHv2
"""

import threading, socket, time, random, os
from datetime import datetime
import logger as hp_log
import session_recorder as sr
import alert_system as alerts
try:
    import docker_sandbox as dsb
    _DSB_OK = True
except ImportError:
    _DSB_OK = False

try:
    import paramiko
    from paramiko import RSAKey, Transport, ServerInterface
    from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL
    from paramiko import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    PARA_OK = True
except ImportError:
    PARA_OK = False
    class ServerInterface:
        pass
    AUTH_FAILED = 1
    AUTH_SUCCESSFUL = 0
    OPEN_SUCCEEDED = 0
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED = 1
    class Transport:
        def __init__(self, *a, **kw): pass
    class RSAKey:
        @staticmethod
        def generate(bits): return None
        def write_private_key_file(self, path): pass
        def __init__(self, filename=None): pass

os.makedirs("logs", exist_ok=True)
HOST_KEY_PATH = "logs/ssh_host_rsa.key"

def _get_key():
    if os.path.exists(HOST_KEY_PATH):
        return RSAKey(filename=HOST_KEY_PATH)
    k = RSAKey.generate(2048)
    k.write_private_key_file(HOST_KEY_PATH)
    return k

# ── Fake filesystem ────────────────────────────────────────────────────────────
FS_DIRS = {
    "/":                ["bin", "boot", "dev", "etc", "home", "lib", "media",
                         "mnt", "opt", "proc", "root", "run", "sbin", "srv",
                         "sys", "tmp", "usr", "var"],
    "/home":            ["admin"],
    "/home/admin":      [".bash_history", ".bashrc", "notes.txt",
                         "backup_creds.txt", "scripts"],
    "/home/admin/scripts": ["backup.sh", "deploy.sh", "cleanup.sh"],
    "/var":             ["backups", "log", "mail", "opt", "run", "spool", "www"],
    "/var/www":         ["html"],
    "/var/www/html":    ["index.php", "config.php", "db.php",
                         "admin.php", "wp-config.php"],
    "/var/log":         ["apache2", "auth.log", "syslog", "kern.log",
                         "mysql", "nginx"],
    "/var/backups":     ["backup_2025-03-01.tar.gz", "mysql_dump.sql",
                         "passwd.bak", "shadow.bak"],
    "/etc":             ["passwd", "hosts", "hostname", "crontab",
                         "nginx", "mysql", "ssh", "apt"],
    "/etc/mysql":       ["my.cnf", "debian.cnf"],
    "/etc/ssh":         ["sshd_config", "ssh_host_rsa_key.pub"],
    "/tmp":             ["sess_ab3f92", "upload_tmp_0x44", ".ICE-unix"],
    "/root":            [".bash_history", ".ssh", ".bashrc"],
    "/root/.ssh":       ["authorized_keys", "known_hosts", "id_rsa.pub"],
}

FILE_CONTENT = {
    "/etc/passwd":
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "mysql:x:120:125:MySQL Server:/nonexistent:/bin/false\n"
        "admin:x:1000:1000:LCF Admin:/home/admin:/bin/bash\n",

    "/etc/hosts":
        "127.0.0.1 localhost\n"
        "127.0.1.1 lcf-core01\n"
        "172.18.0.1 db.laxmichitfund.internal\n"
        "172.18.0.2 mail.laxmichitfund.internal\n",

    "/etc/hostname":
        "lcf-core01\n",

    "/etc/mysql/my.cnf":
        "[client]\nport = 3306\nsocket = /var/run/mysqld/mysqld.sock\n\n"
        "[mysqld]\nuser = mysql\npid-file = /var/run/mysqld/mysqld.pid\n"
        "socket = /var/run/mysqld/mysqld.sock\nport = 3306\n"
        "datadir = /var/lib/mysql\nbind-address = 127.0.0.1\n",

    "/etc/ssh/sshd_config":
        "Port 22\nProtocol 2\nHostKey /etc/ssh/ssh_host_rsa_key\n"
        "PermitRootLogin yes\nPasswordAuthentication yes\n"
        "MaxAuthTries 6\nX11Forwarding yes\n"
        "PrintMotd no\nAcceptEnv LANG LC_*\n",

    "/var/www/html/config.php":
        "<?php\ndefine('DB_HOST', 'localhost');\n"
        "define('DB_NAME', 'lcf_ledger');\n"
        "define('DB_USER', 'lcf_admin');\n"
        "define('DB_PASS', '***REMOVED***');\n"
        "define('SITE_URL', 'https://laxmichitfund.internal');\n?>\n",

    "/var/www/html/wp-config.php":
        "<?php\ndefine('DB_NAME', 'lcf_wiki');\n"
        "define('DB_USER', 'wp_admin');\n"
        "define('DB_PASSWORD', '***REMOVED***');\n"
        "define('DB_HOST', 'localhost');\n"
        "define('AUTH_KEY', '***REMOVED***');\n?>\n",

    "/home/admin/.bash_history":
        "    1  ssh admin@backup-server.laxmichitfund.internal\n"
        "    2  mysql -u root -p\n"
        "    3  mysqldump -u lcf_admin -p lcf_ledger > /var/backups/portal_backup.sql\n"
        "    4  tar -czf /var/backups/full_backup_2025.tar.gz /var/www/html\n"
        "    5  cd /var/www/html\n"
        "    6  vim config.php\n"
        "    7  grep -r 'password' /var/www/\n"
        "    8  tail -f /var/log/apache2/access.log\n"
        "    9  cat /etc/passwd | grep -v nologin\n"
        "   10  netstat -tulpn\n"
        "   11  ps aux | grep php\n"
        "   12  systemctl status nginx\n"
        "   13  systemctl status mysql\n"
        "   14  cd /var/backups && ls -lh\n"
        "   15  php /var/www/html/cron.php\n"
        "   16  cat /var/log/auth.log | tail -50\n"
        "   17  find / -name '*.php' -newer /var/www/html/index.php 2>/dev/null\n"
        "   18  openssl rand -base64 32\n"
        "   19  history\n",

    "/home/admin/notes.txt":
        "Admin Notes - DO NOT SHARE\n"
        "DB password stored in KeePass - vault at /home/admin/vault.kdbx\n"
        "Backup runs every Sunday 3AM via cron\n"
        "FTP disabled for external - use SFTP only\n",

    "/home/admin/backup_creds.txt":
        "# Backup credentials\n"
        "# CONFIDENTIAL - Internal use only\n"
        "backup_user: lcf_backup\n"
        "backup_host: 172.18.0.50\n"
        "note: password rotated quarterly - see KeePass\n",

    "/var/log/auth.log":
        "Mar 14 09:00:01 lcf-core01 sshd[1234]: Accepted password for admin from 192.168.1.1 port 54321 ssh2\n"
        "Mar 14 09:42:11 lcf-core01 sshd[1235]: Failed password for root from 203.0.113.42 port 41234 ssh2\n"
        "Mar 14 10:15:33 lcf-core01 sshd[1236]: Failed password for admin from 185.220.101.5 port 39822 ssh2\n",

    "/var/backups/passwd.bak":
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:1000:1000::/home/admin:/bin/bash\n",

    "/root/.bash_history":
        "    1  apt update && apt upgrade -y\n"
        "    2  cat /etc/shadow\n"
        "    3  mysql -u root -p\n"
        "    4  grep password /var/www/html/config.php\n"
        "    5  ssh-keygen -t rsa -b 4096\n"
        "    6  ufw allow 22/tcp\n"
        "    7  ufw allow 80/tcp\n"
        "    8  ufw allow 443/tcp\n"
        "    9  ufw enable\n"
        "   10  tail -f /var/log/auth.log\n"
        "   11  passwd admin\n"
        "   12  history -c\n",


    "/var/log/apache2/access.log":
        "192.168.1.1 - - [14/Mar/2025:09:12:33 +0530] \"GET /admin/dashboard HTTP/1.1\" 200 4823\n"
        "203.0.113.42 - - [14/Mar/2025:10:22:15 +0530] \"GET /admin/export HTTP/1.1\" 403 287\n"
        "185.220.101.5 - - [14/Mar/2025:11:05:44 +0530] \"GET /backup/users_dump.sql HTTP/1.1\" 200 1842\n"
        "198.51.100.7 - - [14/Mar/2025:11:06:01 +0530] \"GET /.env HTTP/1.1\" 200 156\n"
        "10.0.0.5 - - [14/Mar/2025:12:31:22 +0530] \"POST /admin/login HTTP/1.1\" 200 512\n"
        "45.155.205.9 - - [14/Mar/2025:13:44:18 +0530] \"GET /admin/search?q=%27+OR+1=1-- HTTP/1.1\" 500 1024\n",

    "/var/log/syslog":
        "Mar 14 09:00:01 lcf-core01 CRON[1234]: (root) CMD (/home/admin/scripts/backup.sh)\n"
        "Mar 14 09:00:04 lcf-core01 sshd[1235]: Accepted password for admin from 192.168.1.1 port 54321 ssh2\n"
        "Mar 14 09:05:11 lcf-core01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DST=172.18.0.100 PROTO=TCP DPT=22\n"
        "Mar 14 10:15:33 lcf-core01 mysqld[822]: [Warning] Access denied for user from host 203.0.113.42\n"
        "Mar 14 11:22:44 lcf-core01 postfix/smtpd[1400]: connect from unknown[185.220.101.5]\n"
        "Mar 14 12:00:01 lcf-core01 CRON[1500]: (admin) CMD (/usr/sbin/logrotate /etc/logrotate.conf)\n",

    "/var/log/apache2/error.log":
        "[Thu Mar 14 09:42:11.334821 2025] [error] [pid 901] [client 203.0.113.42:41234] "
        "PHP Warning: mysqli_connect(): Access denied for user 'lcf_admin'@'localhost' "
        "in /var/www/html/db.php on line 12\n"
        "[Thu Mar 14 11:05:44.112233 2025] [error] [pid 902] [client 198.51.100.7:39822] "
        "File does not exist: /var/www/html/.env\n",

    "/var/log/nginx/access.log":
        "192.168.1.1 - - [14/Mar/2025:09:12:33 +0530] \"GET / HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"\n"
        "203.0.113.42 - - [14/Mar/2025:10:22:15 +0530] \"GET /robots.txt HTTP/1.1\" 200 221 \"-\" \"Go-http-client/1.1\"\n",

    "/home/admin/database.yml":
        "# Database configuration\n"
        "production:\n"
        "  adapter: mysql2\n"
        "  encoding: utf8mb4\n"
        "  host: localhost\n"
        "  port: 3306\n"
        "  database: lcf_ledger\n"
        "  username: lcf_admin\n"
        "  password: ***REMOVED***\n"
        "  pool: 10\n"
        "  timeout: 5000\n\n"
        "backup:\n"
        "  adapter: mysql2\n"
        "  host: 172.18.0.50\n"
        "  database: lcf_ledger_archive\n"
        "  username: backup_user\n"
        "  password: ***REMOVED***\n",

    "/home/admin/.env":
        "APP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://laxmichitfund.internal\n\n"
        "DB_CONNECTION=mysql\nDB_HOST=localhost\nDB_PORT=3306\n"
        "DB_DATABASE=lcf_ledger\nDB_USERNAME=lcf_admin\nDB_PASSWORD=***REMOVED***\n\n"
        "REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=***REMOVED***\nREDIS_PORT=6379\n\n"
        "JWT_SECRET=***REMOVED***\nJWT_EXPIRY=3600\n"
        "AWS_ACCESS_KEY_ID=***REMOVED***\nAWS_SECRET_ACCESS_KEY=***REMOVED***\nAWS_REGION=ap-south-1\n",

    "/home/admin/config.ini":
        "[database]\n"
        "host     = localhost\n"
        "port     = 3306\n"
        "name     = lcf_ledger\n"
        "user     = lcf_admin\n"
        "password = ***REMOVED***\n\n"
        "[redis]\n"
        "host     = 127.0.0.1\n"
        "port     = 6379\n"
        "password = ***REMOVED***\n\n"
        "[mail]\n"
        "smtp_host = mail.laxmichitfund.internal\n"
        "smtp_port = 587\n"
        "username  = noreply@laxmichitfund.internal\n"
        "password  = ***REMOVED***\n\n"
        "[app]\n"
        "secret_key = ***REMOVED***\n"
        "debug      = false\n"
        "timezone   = Asia/Kolkata\n",

    "/var/www/html/database.php":
        "<?php\n"
        "return [\n"
        "    'default' => 'mysql',\n"
        "    'connections' => [\n"
        "        'mysql' => [\n"
        "            'host'     => env('DB_HOST', 'localhost'),\n"
        "            'database' => env('DB_DATABASE', 'lcf_ledger'),\n"
        "            'username' => env('DB_USERNAME', 'lcf_admin'),\n"
        "            'password' => env('DB_PASSWORD', '***REMOVED***'),\n"
        "        ],\n"
        "    ],\n"
        "];\n",

    "/home/admin/scripts/backup.sh":
        "#!/bin/bash\n# LCF Backup Script\nDATE=$(date +%Y%m%d)\n"
        "mysqldump -u lcf_admin -p'***' lcf_ledger > /var/backups/mysql_$DATE.sql\n"
        "tar -czf /var/backups/www_$DATE.tar.gz /var/www/html/\n"
        "echo 'Backup complete' | mail -s 'Backup' admin@laxmichitfund.internal\n",
}

# ── Fake command responses ─────────────────────────────────────────────────────
FIXED_RESPONSES = {
    "whoami":        "admin",
    "id":            "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)",
    "uname":         "Linux",
    "uname -a":      "Linux lcf-core01 5.15.0-97-generic #107-Ubuntu SMP Wed Feb 7 13:26:48 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
    "hostname":      "lcf-core01",
    "hostname -f":   "lcf-core01.laxmichitfund.internal",
    "date":          lambda: datetime.now().strftime("%a %b %d %H:%M:%S IST %Y"),
    "uptime":        lambda: f" {datetime.now().strftime('%H:%M:%S')} up {random.choice([31,42,56,63,77])} days,  {random.randint(1,23)}:{random.randint(10,59):02d},  1 user,  load average: 0.{random.randint(10,80)}, 0.{random.randint(10,80)}, 0.{random.randint(10,50)}",
    "w":             lambda: f" {datetime.now().strftime('%H:%M:%S')} up 42 days,  3:17,  1 user,  load average: 0.15, 0.22, 0.18\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\nadmin    pts/0    {random.choice(['10.0.0.1','192.168.1.5'])}        09:00    0.00s  0.01s  0.00s w",
    "ps":            "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 1235 pts/0    00:00:00 ps",
    "ps aux": (
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root           1  0.0  0.1 169936 11204 ?        Ss   Mar13   0:08 /sbin/init\n"
        "root           2  0.0  0.0      0     0 ?        S    Mar13   0:00 [kthreadd]\n"
        "root         421  0.0  0.1  15424  9844 ?        Ss   Mar13   0:00 /usr/sbin/sshd -D\n"
        "root         580  0.0  0.0  55680  3540 ?        Ss   Mar13   0:00 nginx: master process /usr/sbin/nginx\n"
        "www-data     581  0.1  0.5  56344 42112 ?        S    Mar13   0:22 nginx: worker process\n"
        "www-data     582  0.1  0.5  56344 41988 ?        S    Mar13   0:21 nginx: worker process\n"
        "www-data     601  0.2  1.2 408832 98304 ?        S    Mar13   1:14 php-fpm: pool www\n"
        "www-data     602  0.2  1.1 408832 94208 ?        S    Mar13   1:09 php-fpm: pool www\n"
        "mysql        822  0.3  5.2 1842432 421888 ?      Ssl  Mar13   4:32 /usr/sbin/mysqld\n"
        "redis        950  0.1  0.4  65536 32768 ?        Ssl  Mar13   1:44 /usr/bin/redis-server 127.0.0.1:6379\n"
        "postfix     1400  0.0  0.1  62120  9216 ?        Ss   Mar13   0:01 /usr/lib/postfix/sbin/master\n"
        "postfix     1401  0.0  0.1  62248  9344 ?        S    Mar13   0:00 pickup -l -t unix -u\n"
        "postfix     1402  0.0  0.1  62248  9344 ?        S    Mar13   0:00 qmgr -l -t unix -u\n"
        "root        1100  0.0  0.1  15872  8192 ?        Ss   Mar13   0:00 proftpd: (accepting connections)\n"
        "elasticsearch 1050 1.2 8.4 3670016 688128 ? Ssl  Mar13  18:42 /usr/share/elasticsearch/jdk/bin/java\n"
        "root        1300  0.0  0.2  63232 18432 ?        Ss   Mar13   0:04 /usr/sbin/named -u bind\n"
        "root        1500  0.0  0.0  15428  1024 ?        Ss   Mar13   0:00 /usr/sbin/cron -f\n"
        "root        1501  0.0  0.0  57188  3584 ?        Ss   Mar13   0:00 /lib/systemd/systemd-journald\n"
        "admin       1234  0.0  0.1  22528 10240 pts/0    Ss   09:00   0:00 -bash\n"
        "admin       1888  0.0  0.0  10752  3584 pts/0    R+   09:42   0:00 ps aux\n"
    ),
    "ps -ef": (
        "UID          PID    PPID  C STIME TTY          TIME CMD\n"
        "root           1       0  0 Mar13 ?        00:00:08 /sbin/init splash\n"
        "root         421       1  0 Mar13 ?        00:00:00 /usr/sbin/sshd -D\n"
        "root         580       1  0 Mar13 ?        00:00:00 nginx: master process /usr/sbin/nginx -g daemon on\n"
        "www-data     581     580  0 Mar13 ?        00:00:22 nginx: worker process\n"
        "www-data     601     580  0 Mar13 ?        00:01:14 php-fpm: pool www\n"
        "mysql        822       1  0 Mar13 ?        00:04:32 /usr/sbin/mysqld\n"
        "redis        950       1  0 Mar13 ?        00:01:44 /usr/bin/redis-server 127.0.0.1:6379\n"
        "postfix     1400       1  0 Mar13 ?        00:00:01 /usr/lib/postfix/sbin/master -w\n"
        "root        1100       1  0 Mar13 ?        00:00:00 proftpd: (accepting connections)\n"
        "root        1500       1  0 Mar13 ?        00:00:00 /usr/sbin/cron -f\n"
        "admin       1234     421  0 09:00 pts/0    00:00:00 -bash\n"
        "admin       1889    1234  0 09:42 pts/0    00:00:00 ps -ef\n"
    ),
    "env":           "HOME=/home/admin\nUSER=admin\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nSHELL=/bin/bash\nLANG=en_IN.UTF-8\nTERM=xterm-256color",
    "ifconfig":      "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 172.18.0.100  netmask 255.255.0.0  broadcast 172.18.255.255\n        ether 02:42:ac:12:00:64  txqueuelen 0  (Ethernet)\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0",
    "ip a":          "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 172.18.0.100/16 brd 172.18.255.255 scope global eth0",
    "ip addr":       "1: lo: <LOOPBACK,UP,LOWER_UP>\n    inet 127.0.0.1/8\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    inet 172.18.0.100/16",
    "netstat -tulpn":(
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1235/sshd\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      901/nginx\n"
        "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      901/nginx\n"
        "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      822/mysqld\n"
        "tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      1100/proftpd\n"
        "tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      1400/postfix\n"
        "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      950/redis-server\n"
        "tcp        0      0 127.0.0.1:9200          0.0.0.0:*               LISTEN      1050/elasticsearch\n"
        "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1150/postgres\n"
        "udp        0      0 0.0.0.0:53              0.0.0.0:*                           1300/named\n"
    ),
    "ss -tulpn":(
        "Netid  State   Recv-Q Send-Q  Local Address:Port    Process\n"
        "tcp    LISTEN  0      128     0.0.0.0:22              users:((sshd,pid=1235))\n"
        "tcp    LISTEN  0      511     0.0.0.0:80              users:((nginx,pid=901))\n"
        "tcp    LISTEN  0      511     0.0.0.0:443             users:((nginx,pid=901))\n"
        "tcp    LISTEN  0      128     0.0.0.0:21              users:((proftpd,pid=1100))\n"
        "tcp    LISTEN  0      80      127.0.0.1:3306          users:((mysqld,pid=822))\n"
        "tcp    LISTEN  0      128     0.0.0.0:25              users:((master,pid=1400))\n"
        "tcp    LISTEN  0      511     127.0.0.1:6379          users:((redis-server,pid=950))\n"
        "tcp    LISTEN  0      128     127.0.0.1:9200          users:((elasticsearch,pid=1050))\n"
        "udp    UNCONN  0      0       0.0.0.0:53              users:((named,pid=1300))\n"
    ),
    "df":            "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       51475068 18542912  30286412  39% /\ntmpfs             4096012        0   4096012   0% /dev/shm",
    "df -h":         "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   18G   29G  39% /\ntmpfs           3.9G     0  3.9G   0% /dev/shm",
    "free":          "              total        used        free      shared  buff/cache   available\nMem:        8189060     3124512     1748036      204512     3316512     4626024\nSwap:       2097148      102400     1994748",
    "free -h":       "              total        used        free      shared  buff/cache   available\nMem:          7.8Gi       2.9Gi       1.6Gi       200Mi       3.1Gi       4.4Gi\nSwap:         2.0Gi       100Mi       1.9Gi",
    "history":(
        "    1  ssh admin@backup-server.laxmichitfund.internal\n"
        "    2  mysql -u root -p\n"
        "    3  mysqldump -u lcf_admin -p lcf_ledger > /var/backups/portal_backup.sql\n"
        "    4  tar -czf /var/backups/full_backup_2025.tar.gz /var/www/html\n"
        "    5  cd /var/www/html\n"
        "    6  vim config.php\n"
        "    7  grep -r 'password' /var/www/\n"
        "    8  tail -f /var/log/apache2/access.log\n"
        "    9  cat /etc/passwd | grep -v nologin\n"
        "   10  netstat -tulpn\n"
        "   11  ps aux | grep nginx\n"
        "   12  systemctl status nginx\n"
        "   13  cd /var/backups && ls -lh\n"
        "   14  php /var/www/html/cron.php\n"
        "   15  openssl rand -base64 32\n"
        "   16  history\n"
    ),
    "last":          "admin    pts/0        192.168.1.1      Thu Mar 14 09:00   still logged in\nadmin    pts/0        10.0.0.5         Wed Mar 13 16:22 - 18:45  (02:23)\nwtmp begins Mon Mar 11 08:00:00 2025",
    "which python":  "/usr/bin/python3",
    "which python3": "/usr/bin/python3",
    "python3 --version": "Python 3.10.12",
    "mysql --version": "mysql  Ver 8.0.32 Distrib 8.0.32, for Linux (x86_64)",
    "php --version": "PHP 8.0.30 (cli)\nCopyright (c) The PHP Group",
    "apache2 -v":    "Server version: Apache/2.4.57 (Ubuntu)\nServer built:   2023-10-19T13:38:42",
    "nginx -v":      "nginx version: nginx/1.24.0",
    "crontab -l": (
        "# LCF Core Crontab\n"
        "# m h  dom mon dow   command\n"
        "0 3 * * 0 /home/admin/scripts/backup.sh >> /var/log/backup.log 2>&1\n"
        "0 */6 * * * /usr/sbin/logrotate /etc/logrotate.conf\n"
        "*/5 * * * * /usr/bin/php /var/www/html/cron.php > /dev/null 2>&1\n"
        "0 2 * * * /usr/bin/mysqldump -u lcf_admin -p'***' lcf_ledger > /var/backups/mysql_daily.sql\n"
        "30 1 * * 0 /usr/bin/find /tmp -mtime +7 -delete\n"
        "0 */12 * * * /usr/bin/certbot renew --quiet\n"
        "*/10 * * * * /usr/lib/nagios/plugins/check_disk -w 20 -c 10 -p /\n"
    ),
    "exit":          "__EXIT__",
    "logout":        "__EXIT__",
    "quit":          "__EXIT__",
}

BLOCKED = {
    "sudo", "su", "chmod", "chown", "rm", "mv",
    "wget", "curl", "nc", "netcat", "ncat",
    "python -c", "python3 -c", "perl -e",
    "bash -i", "sh -i", "/bin/bash", "/bin/sh",
    "mkfifo", "mknod",
}


def _handle_cmd(cmd: str, cwd: str) -> tuple[str, str]:
    """Returns (output, new_cwd)"""
    stripped = cmd.strip()
    if not stripped:
        return "", cwd

    parts = stripped.split()
    base  = parts[0]

    # Exit
    if stripped.lower() in ("exit", "logout", "quit"):
        return "__EXIT__", cwd

    # Blocked commands
    for b in BLOCKED:
        if stripped.startswith(b):
            return f"bash: {base}: Permission denied", cwd

    # Fixed responses
    if stripped in FIXED_RESPONSES:
        v = FIXED_RESPONSES[stripped]
        return (v() if callable(v) else v), cwd
    if base in FIXED_RESPONSES:
        v = FIXED_RESPONSES[base]
        return (v() if callable(v) else v), cwd

    # ── cd ──
    if base == "cd":
        dest = parts[1] if len(parts) > 1 else "/home/admin"
        if dest == "..":
            p = cwd.rstrip("/").rsplit("/", 1)
            new_cwd = p[0] or "/"
        elif dest.startswith("/"):
            new_cwd = dest.rstrip("/") or "/"
        else:
            new_cwd = (cwd.rstrip("/") + "/" + dest)
        if new_cwd in FS_DIRS or any(new_cwd == k for k in FS_DIRS):
            return "", new_cwd
        return f"bash: cd: {dest}: No such file or directory", cwd

    # ── pwd ──
    if base == "pwd":
        return cwd, cwd

    # ── ls ──
    if base == "ls":
        flags = [p for p in parts[1:] if p.startswith("-")]
        target = next((p for p in parts[1:] if not p.startswith("-")), None)
        listing_path = target if target else cwd
        if not listing_path.startswith("/"):
            listing_path = cwd.rstrip("/") + "/" + listing_path

        items = FS_DIRS.get(listing_path, [])
        if not items:
            return f"ls: cannot access '{listing_path}': No such file or directory", cwd

        show_long = "-l" in flags or "-la" in flags or "-al" in flags
        show_all  = "-a" in flags or "-la" in flags or "-al" in flags

        if show_long:
            lines = []
            if show_all:
                lines.append("drwxr-xr-x 2 admin admin 4096 Mar 14 09:00 .")
                lines.append("drwxr-xr-x 3 admin admin 4096 Mar 14 09:00 ..")
            for item in items:
                if isinstance(item, str):
                    lines.append(f"drwxr-xr-x 2 admin admin 4096 Mar 14 09:00 {item}")
                else:
                    lines.append(f"-rw-r--r-- 1 admin admin {random.randint(512,102400)} Mar 14 09:00 {item}")
            return "\n".join(lines), cwd
        else:
            names = []
            if show_all:
                names = [".", ".."]
            for item in items:
                names.append(item if isinstance(item, str) else item)
            return "  ".join(str(n) for n in names), cwd

    # ── cat ──
    if base == "cat":
        if len(parts) < 2:
            return "cat: missing operand", cwd
        target = parts[1]
        if not target.startswith("/"):
            target = cwd.rstrip("/") + "/" + target
        content = FILE_CONTENT.get(target)
        if content:
            return content.rstrip("\n"), cwd
        # Check just filename
        fname = target.split("/")[-1]
        content = FILE_CONTENT.get("/" + fname)
        if content:
            return content.rstrip("\n"), cwd
        return f"cat: {parts[1]}: Permission denied", cwd

    # ── find ──
    if base == "find":
        return "/home/admin\n/home/admin/.bash_history\n/home/admin/notes.txt\n/var/www/html/config.php", cwd

    # ── grep ──
    if base == "grep":
        pattern = parts[1] if len(parts) > 1 else ""
        return f"Binary file /var/www/html/config.php matches\n/etc/passwd:{pattern}::NOLOGIN", cwd

    # ── echo ──
    if base == "echo":
        return " ".join(parts[1:]).replace("$PATH", FIXED_RESPONSES["env"].split("\n")[1].split("=",1)[1]), cwd

    # ── mkdir/touch/nano/vi/vim ──
    if base in ("mkdir", "touch", "nano", "vi", "vim"):
        return f"bash: {base}: Permission denied", cwd

    # ── which ──
    if base == "which":
        binaries = {"ls":"/bin/ls","cat":"/bin/cat","bash":"/bin/bash",
                    "python":"/usr/bin/python3","php":"/usr/bin/php"}
        target = parts[1] if len(parts) > 1 else ""
        return binaries.get(target, f"which: no {target} in PATH"), cwd

    # ── Generic unknown ──
    return f"bash: {base}: command not found", cwd


# ── Paramiko server interface ──────────────────────────────────────────────────
class SSHServer(ServerInterface):
    def __init__(self, ip):
        self.ip  = ip
        self.evt = threading.Event()

    def check_auth_password(self, username, password):
        hp_log.log("SSH_AUTH_ATTEMPT", self.ip, "SSH",
                   username=username, password=password)
        anon_passes = {"anonymous", "guest", "anon", ""}
        if (username == "admin" and password == "admin") or \
           (username.lower() == "anonymous") or \
           password.lower() in anon_passes:
            hp_log.log("SSH_AUTH_SUCCESS", self.ip, "SSH",
                       username=username, password=password)
            return AUTH_SUCCESSFUL
        hp_log.log("SSH_AUTH_FAILURE", self.ip, "SSH",
                   username=username, password=password)
        alerts.record_failed_login(self.ip, "SSH", username, password)
        time.sleep(random.uniform(1.0, 2.5))  # brute-force delay
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED if kind == "session" else OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.evt.set()
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors="replace")
        hp_log.log("SSH_EXEC", self.ip, "SSH", command=cmd)
        out, _ = _handle_cmd(cmd, "/home/admin")
        channel.sendall((out + "\n").encode())
        channel.send_exit_status(0)
        channel.close()
        return True

    def check_channel_pty_request(self, *a): return True
    def get_allowed_auths(self, username):    return "password"


# ── SSH Session thread ─────────────────────────────────────────────────────────
class SSHSession(threading.Thread):
    def __init__(self, conn, addr, host_key):
        super().__init__(daemon=True)
        self.conn     = conn
        self.ip       = addr[0]
        self.host_key = host_key
        self.sid      = hp_log.new_session(self.ip, "SSH")
        self.recorder = None   # set after auth success
        self.sandbox  = None   # Docker sandbox session

    def run(self):
        hp_log.log("SSH_CONNECT", self.ip, "SSH", self.sid)
        transport = None
        try:
            transport = Transport(self.conn)
            transport.add_server_key(self.host_key)
            srv = SSHServer(self.ip)
            transport.start_server(server=srv)

            chan = transport.accept(20)
            if not chan:
                return
            srv.evt.wait(10)
            if not srv.evt.is_set():
                return

            # MOTD
            motd = (
                "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-97-generic x86_64)\r\n"
                "\r\n"
                " * Documentation:  https://help.ubuntu.com\r\n"
                " * System info:    https://landscape.canonical.com\r\n"
                "\r\n"
                "  System load:  0.15              Processes:         124\r\n"
                "  Usage of /:   39.0% of 48.97GB  Users logged in:   1\r\n"
                "  Memory usage: 38%               IPv4 address:      172.18.0.100\r\n"
                "\r\n"
                "Last login: Thu Mar 14 09:00:01 2025 from 192.168.1.1\r\n"
                "\r\n"
            )
            chan.sendall(motd.encode())

            # Start session recorder
            self.recorder = sr.SessionRecorder(
                self.ip, self.sid, username=transport.get_username() or 'unknown'
            )
            self.recorder.record_output(motd.encode())
            self.recorder.record_event('AUTH_SUCCESS',
                f'user={transport.get_username()}')

            # Start Docker sandbox if available
            if _DSB_OK and dsb.is_available():
                self.sandbox = dsb.new_session(self.ip, self.sid)
                hp_log.log('SANDBOX_ATTACHED', self.ip, 'SSH',
                           self.sid, mode='docker')
            else:
                hp_log.log('SANDBOX_ATTACHED', self.ip, 'SSH',
                           self.sid, mode='simulated')

            cwd      = "/home/admin"
            buf      = ""
            cmd_count    = 0
            start_time   = time.time()
            keystroke_times = []
            last_key     = time.time()

            prompt = lambda: f"admin@lcf-core01:{cwd}$ "
            chan.sendall(prompt().encode())

            while True:
                try:
                    chan.settimeout(180)
                    data = chan.recv(1024)
                    if not data:
                        break
                    if self.recorder:
                        self.recorder.record_input(data)
                    for ch in data.decode(errors="replace"):
                        now = time.time()
                        keystroke_times.append(now - last_key)
                        last_key = now

                        if ch in ("\r", "\n"):
                            cmd = buf.strip()
                            buf = ""
                            chan.sendall(b"\r\n")
                            if cmd:
                                cmd_count += 1
                                # Realistic command execution delay
                                time.sleep(random.uniform(0.2, 1.0))
                                hp_log.log("SSH_COMMAND", self.ip, "SSH", self.sid,
                                           command=cmd, cwd=cwd)
                                if self.recorder:
                                    self.recorder.record_command(cmd)
                                # Alert on bait file cat
                                if cmd.startswith('cat '):
                                    fpath = cmd[4:].strip()
                                    if not fpath.startswith('/'):
                                        fpath = cwd.rstrip('/') + '/' + fpath
                                    alerts.check_ssh_file(fpath, self.ip, self.sid)
                                    if self.recorder:
                                        self.recorder.record_event('FILE_READ', fpath)

                                # ── Execute: Docker OR Simulated ──
                                if self.sandbox and self.sandbox.container:
                                    # Real Docker execution
                                    out = self.sandbox.exec(cmd)
                                    cwd_result = self.sandbox.exec('pwd').strip()
                                    if cwd_result and cwd_result.startswith('/'):
                                        cwd = cwd_result
                                else:
                                    # Simulated filesystem fallback
                                    out, cwd = _handle_cmd(cmd, cwd)
                                if out == "__EXIT__":
                                    chan.sendall(b"logout\r\n")
                                    chan.close()
                                    return
                                if out:
                                    out_bytes = (out.replace("\n", "\r\n") + "\r\n").encode()
                                    chan.sendall(out_bytes)
                                    if self.recorder:
                                        self.recorder.record_output(out_bytes)
                            prompt_str = prompt().encode()
                            chan.sendall(prompt_str)
                            if self.recorder:
                                self.recorder.record_output(prompt_str)

                        elif ch == "\x7f":  # backspace
                            if buf:
                                buf = buf[:-1]
                                chan.sendall(b"\x08 \x08")
                        elif ch == "\x03":  # Ctrl+C
                            chan.sendall(b"^C\r\n")
                            chan.sendall(prompt().encode())
                            buf = ""
                        elif ch == "\x04":  # Ctrl+D
                            chan.sendall(b"logout\r\n")
                            chan.close()
                            return
                        else:
                            buf += ch
                            chan.sendall(ch.encode())

                except socket.timeout:
                    chan.sendall(b"\r\ntimed out waiting for input\r\n")
                    break
                except Exception:
                    break

            # Session analytics
            duration = time.time() - start_time
            avg_speed = (sum(keystroke_times) / len(keystroke_times)) if keystroke_times else 0
            hp_log.log("SSH_SESSION_STATS", self.ip, "SSH", self.sid,
                       duration_seconds=round(duration, 2),
                       command_count=cmd_count,
                       avg_keystroke_interval=round(avg_speed, 4))

        except Exception as e:
            hp_log.log("SSH_ERROR", self.ip, "SSH", self.sid, command=str(e))
        finally:
            try:
                if transport:
                    transport.close()
            except Exception:
                pass
            self.conn.close()
            hp_log.end_session(self.sid)
            # Stop Docker sandbox
            if self.sandbox:
                try: self.sandbox.stop()
                except Exception: pass

            if self.recorder:
                info = self.recorder.finish()
                hp_log.log("SESSION_RECORDED", self.ip, "SSH", self.sid,
                           cast_file=info['cast_file'],
                           log_file=info['log_file'],
                           duration=info['duration'],
                           commands=info['commands'])
            hp_log.log("SSH_DISCONNECT", self.ip, "SSH", self.sid)


# ── Server ─────────────────────────────────────────────────────────────────────
_srv     = None
_thread  = None
_running = False

def _accept(sock, host_key):
    while _running:
        try:
            sock.settimeout(1.0)
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            SSHSession(conn, addr, host_key).start()
        except Exception:
            pass

def start(port=22):
    global _srv, _thread, _running
    if not PARA_OK:
        print("[SSH Honeypot] ERROR: paramiko not installed. Run: pip install paramiko")
        return
    host_key = _get_key()
    _srv = socket.socket()
    _srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _srv.bind(("0.0.0.0", port))
    _srv.listen(20)
    _running = True
    _thread = threading.Thread(target=_accept, args=(_srv, host_key), daemon=True)
    _thread.start()
    hp_log.log("SSH_START", "0.0.0.0", "SSH", port=port)
    print(f"[SSH Honeypot] Listening on port {port}")

def stop():
    global _running, _srv
    _running = False
    if _srv:
        _srv.close()
    print("[SSH Honeypot] Stopped")