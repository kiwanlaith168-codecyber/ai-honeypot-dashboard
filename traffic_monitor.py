"""
traffic_monitor.py — Real-time Traffic Pattern Analysis
Detects: rapid-fire connections, scan sweeps, coordinated attacks.
Runs as a background thread alongside the honeypot.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import database as db

logger = logging.getLogger("honeypot.traffic")


class TrafficMonitor:
    """
    Sliding-window rate tracker.
    Keeps a deque of timestamps per IP and raises flags when thresholds are exceeded.
    """

    # ── Thresholds ────────────────────────────────────────────────────────────
    CONN_WINDOW_SEC   = 60     # look-back window in seconds
    MAX_CONNS_PER_MIN = 10     # connections from same IP per minute → suspicious
    RAPID_CMD_SEC     = 2      # commands issued within N seconds of each other
    SCAN_WINDOW_SEC   = 300    # 5-minute window for port/host scan detection

    def __init__(self):
        self._lock        = threading.Lock()
        self._ip_times    = defaultdict(lambda: deque(maxlen=200))
        self._cmd_times   = defaultdict(lambda: deque(maxlen=500))
        self._flags       = {}          # ip → list[flag strings]
        self._running     = False

    # ── Public API ────────────────────────────────────────────────────────────

    def record_connection(self, ip: str):
        with self._lock:
            now = time.time()
            self._ip_times[ip].append(now)
            self._check_connection_rate(ip, now)

    def record_command(self, ip: str, command: str):
        with self._lock:
            now = time.time()
            self._cmd_times[ip].append((now, command))
            self._check_rapid_commands(ip, now)

    def get_flags(self, ip: str) -> list:
        return self._flags.get(ip, [])

    def get_all_suspicious(self) -> dict:
        return {ip: flags for ip, flags in self._flags.items() if flags}

    def start_background_monitor(self):
        """Launch periodic cleanup thread."""
        self._running = True
        t = threading.Thread(target=self._periodic_cleanup, daemon=True)
        t.start()
        logger.info("Traffic monitor started")

    def stop(self):
        self._running = False

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_connection_rate(self, ip: str, now: float):
        cutoff = now - self.CONN_WINDOW_SEC
        recent = [t for t in self._ip_times[ip] if t >= cutoff]
        if len(recent) >= self.MAX_CONNS_PER_MIN:
            flag = (f"RAPID_CONNECTIONS: {len(recent)} connections "
                    f"in {self.CONN_WINDOW_SEC}s")
            self._add_flag(ip, flag)
            logger.warning("🚩 %s — %s", ip, flag)

    def _check_rapid_commands(self, ip: str, now: float):
        q = self._cmd_times[ip]
        if len(q) < 2:
            return
        prev_ts, _ = q[-2]
        if now - prev_ts < self.RAPID_CMD_SEC:
            # Count how many commands in a 10-second burst
            burst = sum(1 for ts, _ in q if now - ts < 10)
            if burst >= 5:
                flag = f"RAPID_COMMANDS: {burst} commands in <10s"
                self._add_flag(ip, flag)

    def _add_flag(self, ip: str, flag: str):
        if ip not in self._flags:
            self._flags[ip] = []
        if flag not in self._flags[ip]:
            self._flags[ip].append(flag)

    def _periodic_cleanup(self):
        """Remove stale entries every 5 minutes."""
        while self._running:
            time.sleep(300)
            now = time.time()
            with self._lock:
                cutoff = now - 3600
                for ip in list(self._ip_times.keys()):
                    self._ip_times[ip] = deque(
                        (t for t in self._ip_times[ip] if t > cutoff),
                        maxlen=200
                    )
                    if not self._ip_times[ip]:
                        del self._ip_times[ip]


# Global singleton
traffic_monitor = TrafficMonitor()
