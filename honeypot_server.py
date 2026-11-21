"""
honeypot_server.py — SSH Honeypot Server v2.0
─────────────────────────────────────────────
NEW in v2.0:
  • Per-command timing (delay_sec) recorded at each keystroke
  • LiveSessionTracker: classifies every command as it arrives
  • Mid-session alert if running risk score crosses LIVE_RISK_ALERT_THRESHOLD
  • SSE live events pushed via shared Queue
  • CommandEvent objects passed to full behavioral analysis at session end
"""

import os
import sys
import time
import uuid
import queue
import socket
import logging
import threading
import textwrap
from datetime import datetime

import paramiko

from config import (
    HONEYPOT_HOST, HONEYPOT_PORT,
    HONEYPOT_USERNAME, HONEYPOT_PASSWORD,
    HONEYPOT_BANNER, FAKE_HOSTNAME, FAKE_OS,
    MAX_SESSIONS, LOG_DIR, LIVE_RISK_ALERT_THRESHOLD,
)
import database as db
from ai_analyzer  import analyze_session, classify_command
from alert_system import check_and_alert, fire_live_alert
from geo          import resolve_ip
from behavior_analyzer import LiveSessionTracker, CommandEvent

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(LOG_DIR, "honeypot.log")),
    ],
)
logger = logging.getLogger("honeypot.server")

# ── Shared SSE event queue (honeypot → Flask /api/live_stream) ────────────────
# app.py reads from this queue to push real-time events to the browser
LIVE_EVENT_QUEUE: queue.Queue = queue.Queue(maxsize=500)

# ── RSA Host Key ──────────────────────────────────────────────────────────────
KEY_FILE = os.path.join(os.path.dirname(__file__), "data", "host_key.pem")

def _get_host_key():
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey(filename=KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    logger.info("Generated RSA host key → %s", KEY_FILE)
    return key

HOST_KEY = _get_host_key()

# ─────────────────────────────────────────────────────────────────────────────
#  Fake Filesystem (unchanged from v1)
# ─────────────────────────────────────────────────────────────────────────────
FAKE_FS = {
    "/":               ["bin","boot","dev","etc","home","lib","media","mnt",
                        "opt","proc","root","run","sbin","srv","sys","tmp","usr","var"],
    "/home":           ["zarqa"],
    "/home/zarqa":     ["notes.txt",".bash_history",".bashrc","project"],
    "/home/zarqa/project": ["server.py","config.yml","README.md"],
    "/etc":            ["passwd","shadow","hosts","hostname","os-release",
                        "network","ssh","cron.d","sudoers","apt","nginx"],
    "/tmp":            [],
    "/var":            ["log","www","cache","spool"],
    "/var/log":        ["auth.log","syslog","kern.log","apache2"],
    "/root":           [".bash_history",".ssh","flag.txt"],
}

FAKE_FILES = {
    "/etc/hostname":    FAKE_HOSTNAME,
    "/etc/os-release":  'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nVERSION_ID="22.04"\n',
    "/etc/hosts":       "127.0.0.1   localhost\n127.0.1.1   ubuntu-server\n::1         localhost\n",
    "/etc/passwd":      "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nzarqa:x:1000:1000:Zarqa,,,:/home/zarqa:/bin/bash\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\n",
    "/etc/shadow":      "Permission denied.\n",
    "/etc/sudoers":     "Permission denied.\n",
    "/root/flag.txt":   "Permission denied.\n",
    "/home/zarqa/notes.txt": "TODO:\n - Fix server configs\n - Update passwords\n - Backup DB\n",
    "/home/zarqa/.bashrc": "# .bashrc\nexport PS1='zarqa@ubuntu-server:~$ '\nalias ll='ls -la'\n",
    "/home/zarqa/.bash_history": "",
    "/var/log/auth.log": "Apr 18 12:01:02 ubuntu-server sshd[1234]: Accepted password for zarqa from 127.0.0.1 port 52234 ssh2\n",
    "/proc/version":    "Linux version 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64\n",
}

FAKE_PACKAGES = [
    "bash 5.1-6ubuntu1","openssh-server 1:8.9p1-3ubuntu0.6",
    "python3 3.10.6-1~22.04","nginx 1.18.0-6ubuntu14.4",
    "mysql-server 8.0.35-0ubuntu0.22.04.1","curl 7.81.0-1ubuntu1.15",
    "wget 1.21.2-2ubuntu1","git 1:2.34.1-1ubuntu1.10",
    "net-tools 1.60+git20181103.0eebece-1ubuntu5","vim 2:8.2.3995-1ubuntu2.15",
]

# ─────────────────────────────────────────────────────────────────────────────
#  Paramiko Server Interface
# ─────────────────────────────────────────────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        self.client_ip  = client_ip
        self.session_id = session_id
        self.event      = threading.Event()

    def check_auth_password(self, username, password):
        logger.info("AUTH  ip=%-16s  user=%s  pass=%s", self.client_ip, username, password)
        if username == HONEYPOT_USERNAME and password == HONEYPOT_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else \
               paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set(); return True

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set(); return True


# ─────────────────────────────────────────────────────────────────────────────
#  Fake Shell — v2.0 with live classification and timing
# ─────────────────────────────────────────────────────────────────────────────

class FakeShell:
    def __init__(self, channel, session_id, client_ip, country="Unknown"):
        self.chan       = channel
        self.session_id = session_id
        self.client_ip  = client_ip
        self.country    = country
        self.cwd        = "/home/zarqa"
        self.seq        = 0
        self.tracker    = LiveSessionTracker(session_id, client_ip)

    def _write(self, data):
        self.chan.send(data.encode())

    def _prompt(self):
        short = self.cwd.replace("/home/zarqa", "~")
        return f"\r\n\033[32mzarqa@{FAKE_HOSTNAME}\033[0m:\033[34m{short}\033[0m$ "

    def _readline(self):
        """Read one line, echoing chars back. Returns (command_str, char_timestamps)."""
        buf        = ""
        char_times = []
        while True:
            try:
                data = self.chan.recv(1024)
            except Exception:
                return buf, char_times
            if not data:
                return buf, char_times
            char = data.decode("utf-8", errors="replace")
            now  = time.time()

            if char in ("\r", "\n", "\r\n"):
                self._write("\r\n")
                return buf.strip(), char_times
            elif char in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    self._write("\x08 \x08")
            elif char == "\x03":
                self._write("^C")
                return "", char_times
            elif char == "\x04":
                return "exit", char_times
            else:
                buf += char
                char_times.append(now)
                self._write(char)

    def run(self):
        self._write(f"\r\nWelcome to {FAKE_OS}\r\n")
        self._write("Last login: Thu Apr 10 09:32:11 2025 from 192.168.1.50\r\n")
        self._write(self._prompt())

        start            = time.time()
        last_cmd_time    = start
        history          = []

        while True:
            cmd, char_times = self._readline()
            if cmd is None:
                break

            now         = time.time()
            delay       = now - last_cmd_time
            last_cmd_time = now

            if cmd:
                self.seq += 1
                output       = self._dispatch(cmd)
                attack_types = classify_command(cmd)

                # ── Save command to DB with timing + classification ────────────
                db.log_command(
                    self.session_id, cmd, output, self.seq,
                    attack_types=attack_types,
                    delay_sec=round(delay, 3),
                )

                # ── Live tracker update ───────────────────────────────────────
                live_status = self.tracker.add_command(
                    self.seq, cmd, now, attack_types
                )

                # ── Push live SSE event ───────────────────────────────────────
                self._push_live_event("command", {
                    **live_status,
                    "country":      self.country,
                    "attack_types": attack_types,
                    "delay_sec":    round(delay, 3),
                })

                # ── Mid-session risk escalation ───────────────────────────────
                if (self.tracker.running_score >= LIVE_RISK_ALERT_THRESHOLD
                        and not self.tracker.alerted):
                    self.tracker.alerted = True
                    threading.Thread(
                        target=fire_live_alert,
                        args=(self.session_id, self.client_ip,
                              self.tracker.running_score, cmd),
                        daemon=True,
                    ).start()
                    self._push_live_event("live_alert", {
                        "session_id":    self.session_id,
                        "ip":            self.client_ip,
                        "country":       self.country,
                        "running_score": self.tracker.running_score,
                        "trigger_cmd":   cmd,
                    })

                history.append(cmd)
                self._write(output.replace("\n", "\r\n"))

            if cmd.lower() in ("exit", "quit", "logout"):
                self._write("\r\nlogout\r\n")
                break

            self._write(self._prompt())

        duration = time.time() - start
        db.close_session(self.session_id, duration)

        # ── Push session-end event ────────────────────────────────────────────
        self._push_live_event("session_end", {
            "session_id": self.session_id,
            "ip":         self.client_ip,
            "country":    self.country,
            "duration":   round(duration, 1),
            "cmd_count":  self.seq,
        })

        logger.info("Session %d ended  ip=%s  duration=%.1fs  cmds=%d",
                    self.session_id, self.client_ip, duration, self.seq)

        # ── Full post-session analysis (background thread) ────────────────────
        threading.Thread(
            target=_post_session_analysis,
            args=(self.session_id, self.client_ip, history,
                  self.tracker.command_events, duration),
            daemon=True,
        ).start()

    def _push_live_event(self, event_type: str, payload: dict):
        """Push event to both the in-memory queue (SSE) and the database."""
        try:
            LIVE_EVENT_QUEUE.put_nowait({
                "event_type": event_type,
                "payload":    payload,
            })
        except queue.Full:
            pass  # drop if queue is full — non-critical
        try:
            db.push_live_event(
                self.session_id, self.client_ip,
                self.country, event_type, payload,
            )
        except Exception:
            pass

    # ── Command dispatcher (same as v1, abbreviated) ──────────────────────────
    def _dispatch(self, raw):
        parts = raw.split()
        if not parts: return ""
        cmd  = parts[0].lower()
        args = parts[1:]
        handlers = {
            "ls": self._cmd_ls, "ll": self._cmd_ls, "dir": self._cmd_ls,
            "pwd": self._cmd_pwd, "cd": self._cmd_cd,
            "whoami": self._cmd_whoami, "id": self._cmd_id,
            "uname": self._cmd_uname, "hostname": self._cmd_hostname,
            "cat": self._cmd_cat, "echo": self._cmd_echo,
            "ps": self._cmd_ps, "top": self._cmd_top,
            "ifconfig": self._cmd_ifconfig, "ip": self._cmd_ip,
            "netstat": self._cmd_netstat, "ss": self._cmd_netstat,
            "history": self._cmd_history, "find": self._cmd_find,
            "grep": self._cmd_grep, "wget": self._cmd_wget,
            "curl": self._cmd_curl, "sudo": self._cmd_sudo,
            "su": self._cmd_su, "chmod": self._cmd_chmod,
            "chown": self._cmd_chmod, "mkdir": self._cmd_mkdir,
            "touch": self._cmd_touch, "rm": self._cmd_rm,
            "cp": self._cmd_cp, "mv": self._cmd_mv,
            "python": self._cmd_python, "python3": self._cmd_python,
            "perl": self._cmd_perl, "php": self._cmd_php,
            "bash": self._cmd_bash, "sh": self._cmd_bash,
            "dpkg": self._cmd_dpkg, "apt": self._cmd_apt,
            "apt-get": self._cmd_apt, "yum": self._cmd_yum,
            "crontab": self._cmd_crontab, "env": self._cmd_env,
            "export": self._cmd_env, "uptime": self._cmd_uptime,
            "free": self._cmd_free, "df": self._cmd_df,
            "lsof": self._cmd_lsof, "nc": self._cmd_nc,
            "ncat": self._cmd_nc, "nmap": self._cmd_nmap,
            "ping": self._cmd_ping, "ssh": self._cmd_ssh,
            "scp": self._cmd_scp, "passwd": self._cmd_passwd,
            "useradd": self._cmd_useradd, "adduser": self._cmd_useradd,
            "clear": lambda a: "\033[2J\033[H",
            "exit": lambda a: "", "quit": lambda a: "", "logout": lambda a: "",
        }
        h = handlers.get(cmd)
        return h(args) if h else f"{raw}: command not found"

    # ── All command handlers (identical to v1) ────────────────────────────────
    def _cmd_ls(self, args):
        path = self.cwd
        for a in args:
            if not a.startswith("-"): path = self._resolve(a)
        entries = FAKE_FS.get(path, [])
        if not entries: return ""
        if any(a.startswith("-") and "l" in a for a in args):
            lines = [f"total {len(entries)*4}"]
            for e in entries:
                ftype = "d" if e in FAKE_FS else "-"
                lines.append(f"{ftype}rwxr-xr-x 1 zarqa zarqa  4096 Apr 10 09:32 {e}")
            return "\n".join(lines)
        return "  ".join(entries)

    def _cmd_pwd(self, a): return self.cwd
    def _cmd_cd(self, args):
        if not args or args[0]=="~": self.cwd="/home/zarqa"; return ""
        t = self._resolve(args[0])
        if t in FAKE_FS or t.startswith("/"): self.cwd=t; return ""
        return f"-bash: cd: {args[0]}: No such file or directory"
    def _cmd_whoami(self, a): return "zarqa"
    def _cmd_id(self, a): return "uid=1000(zarqa) gid=1000(zarqa) groups=1000(zarqa),4(adm),27(sudo)"
    def _cmd_uname(self, args):
        if "-a" in args: return f"Linux {FAKE_HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        if "-r" in args: return "5.15.0-91-generic"
        if "-m" in args: return "x86_64"
        return "Linux"
    def _cmd_hostname(self, a): return FAKE_HOSTNAME
    def _cmd_cat(self, args):
        if not args: return ""
        fpath = self._resolve(args[0])
        content = FAKE_FILES.get(fpath)
        if content is None:
            return f"cat: {args[0]}: Is a directory" if fpath in FAKE_FS \
                   else f"cat: {args[0]}: No such file or directory"
        if content == "Permission denied.\n": return f"cat: {args[0]}: Permission denied"
        return content
    def _cmd_echo(self, args): return " ".join(args)
    def _cmd_ps(self, a):
        return "USER         PID %CPU %MEM    VSZ   RSS STAT COMMAND\nroot           1  0.0  0.0 168828 13152 Ss   /sbin/init\nroot         512  0.0  0.0  14748  1920 Ss   /usr/sbin/sshd -D\nzarqa       1337  0.0  0.1  21948  5248 Ss   -bash\nmysql        442  0.1  2.3 1823456 96200 Sl  /usr/sbin/mysqld\nwww-data     991  0.0  0.1  55616  4608 S    nginx: worker"
    def _cmd_top(self, a): return "top - 09:35:01 up 14 days, 2:03, 1 user, load: 0.12\nTasks: 98 total, 1 running\n%Cpu(s): 1.2 us, 0.5 sy, 98.1 id\nMiB Mem: 3927.7 total, 1243.4 free\n"
    def _cmd_ifconfig(self, a):
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 00:50:56:b5:3a:14  txqueuelen 1000\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0"
    def _cmd_ip(self, args): return self._cmd_ifconfig([])
    def _cmd_netstat(self, a):
        return "Proto Recv-Q Local Address    Foreign Address  State\ntcp   0      0.0.0.0:22      0.0.0.0:*        LISTEN\ntcp   0      0.0.0.0:80      0.0.0.0:*        LISTEN\ntcp   0      0.0.0.0:3306    0.0.0.0:*        LISTEN"
    def _cmd_history(self, a):
        pre = ["    1  sudo apt update","    2  mysql -u root -p","    3  ls -la /var/www"]
        for i, h in enumerate(self.tracker.command_events, 4):
            pre.append(f"    {i}  {h.command}")
        return "\n".join(pre)
    def _cmd_find(self, args):
        p = args[0] if args else self.cwd
        return f"{p}/notes.txt\n{p}/.bashrc\n{p}/.bash_history\n{p}/project/config.yml"
    def _cmd_grep(self, a): return "(grep: simulated — no matches)"
    def _cmd_wget(self, args):
        if not args: return "wget: missing URL"
        url = next((a for a in args if a.startswith("http")), args[-1])
        host = url.split("/")[2] if "/" in url else url
        return f"--2025-04-10 09:35:02--  {url}\nResolving {host}... failed: Name or service not known.\nwget: unable to resolve host address '{host}'"
    def _cmd_curl(self, args):
        if not args: return "curl: try 'curl --help'"
        url = next((a for a in args if a.startswith("http")), args[-1])
        host = url.split("/")[2] if "/" in url else url
        return f"curl: (6) Could not resolve host: {host}"
    def _cmd_sudo(self, args):
        if not args: return "usage: sudo [-AbEefhHiklnPSsvVz] [-g group]..."
        return "[sudo] password for zarqa: \nzarqa is not in the sudoers file.  This incident will be reported."
    def _cmd_su(self, a): return "Password: \nsu: Authentication failure"
    def _cmd_chmod(self, args):
        if len(args) < 2: return "chmod: missing operand"
        return ""
    def _cmd_mkdir(self, args):
        if not args: return "mkdir: missing operand"
        FAKE_FS.setdefault(self.cwd, []).append(args[-1]); return ""
    def _cmd_touch(self, args):
        if not args: return "touch: missing file operand"
        FAKE_FS.setdefault(self.cwd, []).append(args[0]); return ""
    def _cmd_rm(self, args): return "" if [a for a in args if not a.startswith("-")] else "rm: missing operand"
    def _cmd_cp(self, args): return "" if len(args)>=2 else "cp: missing operand"
    def _cmd_mv(self, args): return "" if len(args)>=2 else "mv: missing operand"
    def _cmd_python(self, args):
        if not args or args[0] in ("-V","--version"): return "Python 3.10.12"
        if args[0].endswith(".py"): return f"python3: can't open file '{args[0]}': No such file"
        return "Python 3.10.12\n>>> "
    def _cmd_perl(self, a): return "(perl: executed)"
    def _cmd_php(self, args):
        return "PHP 8.1.2 (cli)" if not args or "-v" in args else "(php: executed)"
    def _cmd_bash(self, args): return "" if not args else f"-bash: {args[0]}: Permission denied"
    def _cmd_dpkg(self, args):
        if "-l" in args:
            lines = ["ii  bash                 5.1-6ubuntu1","ii  openssh-server       1:8.9p1-3ubuntu0.6","ii  python3              3.10.6-1~22.04"]
            return "\n".join(lines)
        return "Use: dpkg -l"
    def _cmd_apt(self, args):
        if not args: return "E: No command"
        if args[0] in ("install","update","upgrade"):
            return "E: Could not open lock file /var/lib/dpkg/lock-frontend (13: Permission denied)"
        return f"E: Invalid operation {args[0]}"
    def _cmd_yum(self, a): return "Error: Use apt on this system."
    def _cmd_crontab(self, args):
        if "-l" in args: return "*/5 * * * * /home/zarqa/project/server.py\n0 2 * * * mysqldump -u root mydb > /backup/db.sql"
        if "-e" in args: return "crontab: installing new crontab"
        return "crontab: usage error"
    def _cmd_env(self, a): return f"SHELL=/bin/bash\nUSER=zarqa\nPATH=/usr/local/bin:/usr/bin:/bin\nHOME=/home/zarqa\nHOSTNAME={FAKE_HOSTNAME}"
    def _cmd_uptime(self, a): return " 09:35:22 up 14 days, 2:06, 1 user, load average: 0.10, 0.08, 0.05"
    def _cmd_free(self, a): return "              total        used        free\nMem:        4021248     1867776     1274368\nSwap:       2097148           0     2097148"
    def _cmd_df(self, a): return "Filesystem      1K-blocks     Used Available Use% Mounted on\n/dev/sda1        51474044 12345678  36509548  26% /\ntmpfs             2010624        0   2010624   0% /dev/shm"
    def _cmd_lsof(self, a): return "COMMAND   PID   USER  FD  TYPE  NAME\nsshd      512   root   3u  IPv4  *:ssh (LISTEN)\nnginx     991   www-data 6u IPv4 *:http (LISTEN)"
    def _cmd_nc(self, a): return "Ncat: Connection refused."
    def _cmd_nmap(self, args):
        t = next((a for a in args if not a.startswith("-")),"localhost")
        return f"Nmap scan report for {t}\nHost seems down.\nNmap done: 1 IP address (0 hosts up) scanned in 3.12 seconds"
    def _cmd_ping(self, args):
        h = args[0] if args else "localhost"
        return f"PING {h}: Name or service not known"
    def _cmd_ssh(self, a): return "ssh: connect to host: Network is unreachable"
    def _cmd_scp(self, a): return "scp: Connection closed"
    def _cmd_passwd(self, a): return "Changing password for zarqa.\nCurrent password: \npasswd: Authentication token manipulation error"
    def _cmd_useradd(self, a): return "useradd: Permission denied."

    def _resolve(self, path):
        if path.startswith("/"): return path.rstrip("/") or "/"
        if path == "..": return self.cwd.rsplit("/",1)[0] or "/"
        if path in (".", "~"): return "/home/zarqa" if path=="~" else self.cwd
        return self.cwd.rstrip("/") + "/" + path


# ─────────────────────────────────────────────────────────────────────────────
#  Post-session pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _post_session_analysis(session_id, ip, commands, command_events, duration):
    try:
        analysis = analyze_session(
            session_id, commands,
            command_events=command_events,
            session_duration=duration,
        )
        check_and_alert(session_id, ip, analysis)
    except Exception as exc:
        logger.error("Post-session analysis failed: %s", exc, exc_info=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Connection handler
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(client_sock, addr):
    client_ip   = addr[0]
    client_port = addr[1]
    session_uuid = str(uuid.uuid4())

    logger.info("NEW CONNECTION  ip=%-16s  port=%d", client_ip, client_port)

    session_id = db.create_session(
        session_uuid, client_ip, client_port, "", ""
    )

    # Resolve geo in background, make country available for shell
    country_holder = ["Unknown"]
    def _geo():
        g = resolve_ip(client_ip)
        db.update_session_geo(session_id, g)
        country_holder[0] = g.get("country", "Unknown")

    threading.Thread(target=_geo, daemon=True).start()

    # Push connection event
    try:
        LIVE_EVENT_QUEUE.put_nowait({
            "event_type": "new_connection",
            "payload": {
                "session_id": session_id,
                "ip":         client_ip,
                "port":       client_port,
            }
        })
    except queue.Full:
        pass

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = HONEYPOT_BANNER
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(client_ip, session_id)
        transport.start_server(server=server)

        channel = transport.accept(30)
        if channel is None:
            return

        server.event.wait(15)
        if not server.event.is_set():
            return

        # Short delay to allow geo thread to resolve country
        time.sleep(0.3)
        shell = FakeShell(channel, session_id, client_ip, country_holder[0])
        shell.run()

    except paramiko.SSHException as e:
        logger.debug("SSH error  ip=%s  %s", client_ip, e)
    except Exception as e:
        logger.error("Handler error  ip=%s  %s", client_ip, e, exc_info=True)
    finally:
        try: client_sock.close()
        except Exception: pass


# ─────────────────────────────────────────────────────────────────────────────
#  Main server loop
# ─────────────────────────────────────────────────────────────────────────────

def start_honeypot():
    db.init_db()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HONEYPOT_HOST, HONEYPOT_PORT))
    server_sock.listen(MAX_SESSIONS)
    logger.info("🍯  Honeypot v2.0 listening on %s:%d", HONEYPOT_HOST, HONEYPOT_PORT)

    active = []
    try:
        while True:
            try:
                client, addr = server_sock.accept()
                t = threading.Thread(
                    target=handle_client, args=(client, addr), daemon=True
                )
                t.start()
                active = [t for t in active if t.is_alive()]
                active.append(t)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error("Accept error: %s", e)
    except KeyboardInterrupt:
        logger.info("Honeypot shutting down…")
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_honeypot()
