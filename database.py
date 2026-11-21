"""
database.py — SQLite Database Manager v2.0
Added: behavioral metadata columns, ai_narrative, live event queries.
"""

import sqlite3
import threading
import json
import logging
from datetime import datetime
from contextlib import contextmanager
from config import DB_PATH

logger = logging.getLogger("honeypot.db")
_local = threading.local()


def get_connection() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


@contextmanager
def db_cursor():
    conn = get_connection()
    cur  = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("DB error: %s", exc, exc_info=True)
        raise


# ─────────────────────────────────────────────────────────────────────────────
#  Schema — v2.0 adds behavioral columns
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    with db_cursor() as cur:

        # sessions — core + geo + behavioral metadata
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            session_uuid     TEXT    UNIQUE NOT NULL,
            ip_address       TEXT    NOT NULL,
            port             INTEGER,
            username         TEXT,
            password         TEXT,
            start_time       TEXT    NOT NULL,
            end_time         TEXT,
            duration_sec     REAL    DEFAULT 0,
            country          TEXT    DEFAULT 'Unknown',
            country_code     TEXT    DEFAULT 'XX',
            city             TEXT    DEFAULT '',
            region           TEXT    DEFAULT '',
            latitude         REAL    DEFAULT 0,
            longitude        REAL    DEFAULT 0,
            isp              TEXT    DEFAULT '',
            is_active        INTEGER DEFAULT 1,
            -- v2.0 behavioral columns
            cmd_per_min      REAL    DEFAULT 0,
            avg_cmd_delay    REAL    DEFAULT 0,
            automation_score REAL    DEFAULT 0,
            attacker_type    TEXT    DEFAULT 'unknown',
            attack_phase     TEXT    DEFAULT 'unknown',
            phase_confidence REAL    DEFAULT 0,
            sensitive_hits   INTEGER DEFAULT 0,
            unique_ratio     REAL    DEFAULT 0
        )""")

        # commands
        cur.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            command     TEXT    NOT NULL,
            output      TEXT    DEFAULT '',
            timestamp   TEXT    NOT NULL,
            seq_num     INTEGER DEFAULT 0,
            attack_types TEXT   DEFAULT '[]',
            delay_sec   REAL    DEFAULT 0
        )""")

        # attacks — AI analysis result
        cur.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id       INTEGER UNIQUE NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            attack_types     TEXT    DEFAULT '[]',
            primary_type     TEXT    DEFAULT 'unknown',
            risk_level       TEXT    DEFAULT 'Low',
            risk_score       INTEGER DEFAULT 0,
            recommendations  TEXT    DEFAULT '',
            ai_narrative     TEXT    DEFAULT '',
            llm_provider     TEXT    DEFAULT 'fallback',
            attacker_type    TEXT    DEFAULT 'unknown',
            attack_phase     TEXT    DEFAULT 'unknown',
            behavior_evidence TEXT   DEFAULT '[]',
            analyzed_at      TEXT
        )""")

        # alerts
        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
            ip_address   TEXT,
            country      TEXT,
            attack_type  TEXT,
            risk_level   TEXT,
            message      TEXT,
            sent_at      TEXT,
            is_live      INTEGER DEFAULT 0,
            acknowledged INTEGER DEFAULT 0
        )""")

        # geo cache
        cur.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip_address   TEXT PRIMARY KEY,
            country      TEXT,
            country_code TEXT,
            city         TEXT,
            region       TEXT,
            latitude     REAL,
            longitude    REAL,
            isp          TEXT,
            cached_at    TEXT
        )""")

        # live events queue (read by SSE, cleared periodically)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS live_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  INTEGER,
            ip_address  TEXT,
            country     TEXT,
            event_type  TEXT,
            payload     TEXT,
            created_at  TEXT
        )""")

    _migrate_existing(cur if False else None)
    logger.info("Database v2.0 ready at %s", DB_PATH)


def _migrate_existing(cur):
    """Add v2.0 columns to existing databases without dropping data."""
    conn = get_connection()
    c    = conn.cursor()
    new_session_cols = [
        ("cmd_per_min",      "REAL DEFAULT 0"),
        ("avg_cmd_delay",    "REAL DEFAULT 0"),
        ("automation_score", "REAL DEFAULT 0"),
        ("attacker_type",    "TEXT DEFAULT 'unknown'"),
        ("attack_phase",     "TEXT DEFAULT 'unknown'"),
        ("phase_confidence", "REAL DEFAULT 0"),
        ("sensitive_hits",   "INTEGER DEFAULT 0"),
        ("unique_ratio",     "REAL DEFAULT 0"),
    ]
    new_attacks_cols = [
        ("ai_narrative",      "TEXT DEFAULT ''"),
        ("llm_provider",      "TEXT DEFAULT 'fallback'"),
        ("attacker_type",     "TEXT DEFAULT 'unknown'"),
        ("attack_phase",      "TEXT DEFAULT 'unknown'"),
        ("behavior_evidence", "TEXT DEFAULT '[]'"),
    ]
    new_commands_cols = [
        ("attack_types", "TEXT DEFAULT '[]'"),
        ("delay_sec",    "REAL DEFAULT 0"),
    ]
    new_alerts_cols = [
        ("is_live", "INTEGER DEFAULT 0"),
    ]
    for col, typedef in new_session_cols:
        try:
            c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {typedef}")
        except Exception:
            pass
    for col, typedef in new_attacks_cols:
        try:
            c.execute(f"ALTER TABLE attacks ADD COLUMN {col} {typedef}")
        except Exception:
            pass
    for col, typedef in new_commands_cols:
        try:
            c.execute(f"ALTER TABLE commands ADD COLUMN {col} {typedef}")
        except Exception:
            pass
    for col, typedef in new_alerts_cols:
        try:
            c.execute(f"ALTER TABLE alerts ADD COLUMN {col} {typedef}")
        except Exception:
            pass
    # Create live_events table
    try:
        c.execute("""
        CREATE TABLE IF NOT EXISTS live_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  INTEGER,
            ip_address  TEXT,
            country     TEXT,
            event_type  TEXT,
            payload     TEXT,
            created_at  TEXT
        )""")
    except Exception:
        pass
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  Session helpers
# ─────────────────────────────────────────────────────────────────────────────

def create_session(session_uuid, ip, port, username, password) -> int:
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO sessions
                (session_uuid,ip_address,port,username,password,start_time)
            VALUES (?,?,?,?,?,?)
        """, (session_uuid, ip, port, username, password,
              datetime.utcnow().isoformat()))
        return cur.lastrowid


def close_session(session_id, duration):
    with db_cursor() as cur:
        cur.execute("""
            UPDATE sessions SET end_time=?,duration_sec=?,is_active=0 WHERE id=?
        """, (datetime.utcnow().isoformat(), duration, session_id))


def update_session_geo(session_id, geo):
    with db_cursor() as cur:
        cur.execute("""
            UPDATE sessions SET
                country=?,country_code=?,city=?,region=?,
                latitude=?,longitude=?,isp=?
            WHERE id=?
        """, (geo.get("country","Unknown"), geo.get("countryCode","XX"),
              geo.get("city",""),          geo.get("regionName",""),
              geo.get("lat",0),            geo.get("lon",0),
              geo.get("isp",""),           session_id))


def update_session_behavior(session_id, meta: dict):
    """Save behavioral metadata after session analysis."""
    with db_cursor() as cur:
        cur.execute("""
            UPDATE sessions SET
                cmd_per_min=?,avg_cmd_delay=?,automation_score=?,
                attacker_type=?,attack_phase=?,phase_confidence=?,
                sensitive_hits=?,unique_ratio=?
            WHERE id=?
        """, (meta.get("commands_per_min", 0),
              meta.get("avg_cmd_delay_sec", 0),
              meta.get("automation_score", 0),
              meta.get("attacker_type", "unknown"),
              meta.get("attack_phase", "unknown"),
              meta.get("phase_confidence", 0),
              meta.get("sensitive_file_hits", 0),
              meta.get("unique_ratio", 0),
              session_id))


def get_session_by_uuid(uuid):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE session_uuid=?", (uuid,))
        return cur.fetchone()


def get_session_by_id(session_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else {}


# ─────────────────────────────────────────────────────────────────────────────
#  Command helpers
# ─────────────────────────────────────────────────────────────────────────────

def log_command(session_id, command, output, seq,
                attack_types=None, delay_sec=0.0):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO commands
                (session_id,command,output,timestamp,seq_num,attack_types,delay_sec)
            VALUES (?,?,?,?,?,?,?)
        """, (session_id, command.strip(), output,
              datetime.utcnow().isoformat(), seq,
              json.dumps(attack_types or []), delay_sec))


def get_commands_for_session(session_id):
    with db_cursor() as cur:
        cur.execute("""
            SELECT * FROM commands WHERE session_id=? ORDER BY seq_num
        """, (session_id,))
        return [dict(r) for r in cur.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
#  Attack / AI helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_attack_analysis(session_id, analysis):
    with db_cursor() as cur:
        cur.execute("""
            INSERT OR REPLACE INTO attacks
                (session_id,attack_types,primary_type,risk_level,risk_score,
                 recommendations,ai_narrative,llm_provider,attacker_type,
                 attack_phase,behavior_evidence,analyzed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (session_id,
              json.dumps(analysis.get("attack_types", [])),
              analysis.get("primary_type", "unknown"),
              analysis.get("risk_level", "Low"),
              analysis.get("risk_score", 0),
              analysis.get("recommendations", ""),
              analysis.get("ai_narrative", ""),
              analysis.get("llm_provider", "fallback"),
              analysis.get("attacker_type", "unknown"),
              analysis.get("attack_phase", "unknown"),
              json.dumps(analysis.get("behavior_evidence", [])),
              datetime.utcnow().isoformat()))


def get_attack_for_session(session_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM attacks WHERE session_id=?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else {}


# ─────────────────────────────────────────────────────────────────────────────
#  Alert helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_alert(session_id, ip, country, attack_type,
               risk_level, message, is_live=False):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO alerts
                (session_id,ip_address,country,attack_type,
                 risk_level,message,sent_at,is_live)
            VALUES (?,?,?,?,?,?,?,?)
        """, (session_id, ip, country, attack_type, risk_level, message,
              datetime.utcnow().isoformat(), 1 if is_live else 0))
        return cur.lastrowid


def get_recent_alerts(limit=20):
    with db_cursor() as cur:
        cur.execute("""
            SELECT * FROM alerts ORDER BY sent_at DESC LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def acknowledge_alert(alert_id):
    with db_cursor() as cur:
        cur.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


# ─────────────────────────────────────────────────────────────────────────────
#  Live events (mid-session SSE)
# ─────────────────────────────────────────────────────────────────────────────

def push_live_event(session_id, ip, country, event_type, payload: dict):
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO live_events
                (session_id,ip_address,country,event_type,payload,created_at)
            VALUES (?,?,?,?,?,?)
        """, (session_id, ip, country, event_type,
              json.dumps(payload), datetime.utcnow().isoformat()))


def get_recent_live_events(since_id=0, limit=50):
    with db_cursor() as cur:
        cur.execute("""
            SELECT * FROM live_events WHERE id>? ORDER BY id DESC LIMIT ?
        """, (since_id, limit))
        return [dict(r) for r in cur.fetchall()]


def cleanup_old_live_events():
    """Keep only the last 500 live events to prevent unbounded growth."""
    with db_cursor() as cur:
        cur.execute("""
            DELETE FROM live_events WHERE id NOT IN (
                SELECT id FROM live_events ORDER BY id DESC LIMIT 500
            )
        """)


# ─────────────────────────────────────────────────────────────────────────────
#  Geo cache
# ─────────────────────────────────────────────────────────────────────────────

def get_cached_geo(ip):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM geo_cache WHERE ip_address=?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None


def cache_geo(ip, geo):
    with db_cursor() as cur:
        cur.execute("""
            INSERT OR REPLACE INTO geo_cache
                (ip_address,country,country_code,city,region,
                 latitude,longitude,isp,cached_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (ip, geo.get("country","Unknown"), geo.get("countryCode","XX"),
              geo.get("city",""), geo.get("regionName",""),
              geo.get("lat",0), geo.get("lon",0),
              geo.get("isp",""), datetime.utcnow().isoformat()))


# ─────────────────────────────────────────────────────────────────────────────
#  Dashboard queries
# ─────────────────────────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    with db_cursor() as cur:
        def q(sql, *args):
            cur.execute(sql, args)
            return cur.fetchone()[0]

        return {
            "total_sessions":  q("SELECT COUNT(*) FROM sessions"),
            "unique_ips":      q("SELECT COUNT(DISTINCT ip_address) FROM sessions"),
            "countries":       q("SELECT COUNT(DISTINCT country) FROM sessions WHERE country!='Unknown'"),
            "high_risk":       q("SELECT COUNT(*) FROM attacks WHERE risk_level='High'"),
            "medium_risk":     q("SELECT COUNT(*) FROM attacks WHERE risk_level='Medium'"),
            "low_risk":        q("SELECT COUNT(*) FROM attacks WHERE risk_level='Low'"),
            "active_sessions": q("SELECT COUNT(*) FROM sessions WHERE is_active=1"),
            "unread_alerts":   q("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
            "bots_detected":   q("SELECT COUNT(*) FROM sessions WHERE attacker_type='automated_bot'"),
            "humans_detected": q("SELECT COUNT(*) FROM sessions WHERE attacker_type='experienced_human'"),
            "total_commands":  q("SELECT COUNT(*) FROM commands"),
        }


def get_recent_sessions(limit=50):
    with db_cursor() as cur:
        cur.execute("""
            SELECT s.*,
                   a.primary_type, a.risk_level, a.risk_score,
                   a.attacker_type AS ai_attacker_type,
                   a.attack_phase  AS ai_attack_phase,
                   a.ai_narrative,
                   (SELECT COUNT(*) FROM commands c WHERE c.session_id=s.id) cmd_count
            FROM sessions s
            LEFT JOIN attacks a ON a.session_id=s.id
            ORDER BY s.start_time DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_session_detail(session_id) -> dict:
    sess  = get_session_by_id(session_id)
    cmds  = get_commands_for_session(session_id)
    atk   = get_attack_for_session(session_id)
    if atk.get("attack_types"):
        try:
            atk["attack_types"] = json.loads(atk["attack_types"])
        except Exception:
            pass
    if atk.get("behavior_evidence"):
        try:
            atk["behavior_evidence"] = json.loads(atk["behavior_evidence"])
        except Exception:
            pass
    return {"session": sess, "commands": cmds, "attack": atk}


def get_attack_type_distribution():
    with db_cursor() as cur:
        cur.execute("""
            SELECT primary_type, COUNT(*) cnt FROM attacks
            GROUP BY primary_type ORDER BY cnt DESC
        """)
        return [dict(r) for r in cur.fetchall()]


def get_country_distribution():
    with db_cursor() as cur:
        cur.execute("""
            SELECT country, country_code, COUNT(*) cnt,
                   AVG(latitude) lat, AVG(longitude) lon
            FROM sessions WHERE country!='Unknown'
            GROUP BY country ORDER BY cnt DESC LIMIT 30
        """)
        return [dict(r) for r in cur.fetchall()]


def get_attacks_last_7_days():
    with db_cursor() as cur:
        cur.execute("""
            SELECT DATE(start_time) day, COUNT(*) cnt
            FROM sessions WHERE DATE(start_time)>=DATE('now','-6 days')
            GROUP BY day ORDER BY day
        """)
        return [dict(r) for r in cur.fetchall()]


def get_map_markers():
    with db_cursor() as cur:
        cur.execute("""
            SELECT ip_address,country,country_code,city,region,
                   latitude,longitude,COUNT(*) attack_count,
                   MAX(COALESCE(a.risk_level,'Low')) max_risk,
                   MAX(COALESCE(s.attacker_type,'unknown')) attacker_type
            FROM sessions s
            LEFT JOIN attacks a ON a.session_id=s.id
            WHERE latitude!=0 AND longitude!=0
            GROUP BY ip_address
        """)
        return [dict(r) for r in cur.fetchall()]


def get_top_attackers(limit=10):
    with db_cursor() as cur:
        cur.execute("""
            SELECT ip_address, country, country_code,
                   COUNT(*) sessions,
                   MAX(COALESCE(a.risk_level,'Low')) max_risk,
                   MAX(s.attacker_type) attacker_type,
                   SUM((SELECT COUNT(*) FROM commands c WHERE c.session_id=s.id)) total_cmds
            FROM sessions s
            LEFT JOIN attacks a ON a.session_id=s.id
            GROUP BY ip_address ORDER BY sessions DESC LIMIT ?
        """, (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_all_commands_paginated(page=1, per_page=100):
    offset = (page - 1) * per_page
    with db_cursor() as cur:
        cur.execute("""
            SELECT c.*, s.ip_address, s.country,
                   c.attack_types
            FROM commands c JOIN sessions s ON s.id=c.session_id
            ORDER BY c.timestamp DESC LIMIT ? OFFSET ?
        """, (per_page, offset))
        return [dict(r) for r in cur.fetchall()]


def get_attacker_type_distribution():
    with db_cursor() as cur:
        cur.execute("""
            SELECT attacker_type, COUNT(*) cnt
            FROM sessions WHERE attacker_type!='unknown'
            GROUP BY attacker_type ORDER BY cnt DESC
        """)
        return [dict(r) for r in cur.fetchall()]


def get_attack_phase_distribution():
    with db_cursor() as cur:
        cur.execute("""
            SELECT attack_phase, COUNT(*) cnt
            FROM sessions WHERE attack_phase!='unknown'
            GROUP BY attack_phase ORDER BY cnt DESC
        """)
        return [dict(r) for r in cur.fetchall()]
