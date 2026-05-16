import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB = Path("data/honeypot.db")

def init_db():
    DB.parent.mkdir(exist_ok=True)
    con = _con()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT    NOT NULL,
            type        TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            port        INTEGER,
            severity    TEXT    DEFAULT 'low',
            data        TEXT    DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    NOT NULL,
            started_at  TEXT    NOT NULL,
            ended_at    TEXT,
            service     TEXT,
            keylog      TEXT    DEFAULT '[]',
            commands    TEXT    DEFAULT '[]',
            credentials TEXT    DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS attackers (
            ip          TEXT    PRIMARY KEY,
            first_seen  TEXT,
            last_seen   TEXT,
            hit_count   INTEGER DEFAULT 1,
            threat_score INTEGER DEFAULT 0,
            geo         TEXT    DEFAULT '{}',
            fingerprint TEXT    DEFAULT '{}',
            real_ips    TEXT    DEFAULT '[]',
            tools       TEXT    DEFAULT '[]',
            blocked     INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS honeytokens (
            token       TEXT PRIMARY KEY,
            label       TEXT,
            created_at  TEXT,
            triggered   INTEGER DEFAULT 0,
            triggered_by TEXT   DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    """)
    con.close()

def _con():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def log_event(type: str, ip: str, port: int = None, severity: str = "low", data: dict = None):
    con = _con()
    con.execute(
        "INSERT INTO events (ts,type,ip,port,severity,data) VALUES (?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), type, ip, port, severity, json.dumps(data or {}))
    )
    con.execute("""
        INSERT INTO attackers (ip,first_seen,last_seen,hit_count) VALUES (?,?,?,1)
        ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, hit_count=hit_count+1
    """, (ip, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
    con.commit(); con.close()

def upsert_attacker(ip: str, **kwargs):
    con = _con()
    for k, v in kwargs.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        con.execute(f"UPDATE attackers SET {k}=? WHERE ip=?", (v, ip))
    con.execute("""
        INSERT OR IGNORE INTO attackers (ip,first_seen,last_seen) VALUES (?,?,?)
    """, (ip, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
    con.commit(); con.close()

def new_session(ip: str, service: str) -> int:
    con = _con()
    cur = con.execute(
        "INSERT INTO sessions (ip,started_at,service) VALUES (?,?,?)",
        (ip, datetime.utcnow().isoformat(), service)
    )
    sid = cur.lastrowid; con.commit(); con.close()
    return sid

def update_session(sid: int, **kwargs):
    con = _con()
    for k, v in kwargs.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        con.execute(f"UPDATE sessions SET {k}=? WHERE id=?", (v, sid))
    con.commit(); con.close()

def close_session(sid: int):
    con = _con()
    con.execute("UPDATE sessions SET ended_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), sid))
    con.commit(); con.close()

def get_events(limit=200):
    con = _con()
    rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [_row(r) for r in rows]

def get_attacker(ip: str):
    con = _con()
    row = con.execute("SELECT * FROM attackers WHERE ip=?", (ip,)).fetchone()
    con.close()
    return _row(row) if row else None

def get_attackers(limit=50):
    con = _con()
    rows = con.execute("SELECT * FROM attackers ORDER BY threat_score DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [_row(r) for r in rows]

def get_sessions(limit=50):
    con = _con()
    rows = con.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [_row(r) for r in rows]

def get_stats():
    con = _con()
    s = {
        "total_events":    con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "unique_attackers":con.execute("SELECT COUNT(*) FROM attackers").fetchone()[0],
        "ssh_sessions":    con.execute("SELECT COUNT(*) FROM sessions WHERE service='ssh'").fetchone()[0],
        "web_hits":        con.execute("SELECT COUNT(*) FROM events WHERE type LIKE 'web_%'").fetchone()[0],
        "high_severity":   con.execute("SELECT COUNT(*) FROM events WHERE severity='high'").fetchone()[0],
        "top_ips": [{"ip":r[0],"count":r[1]} for r in con.execute(
            "SELECT ip,COUNT(*) c FROM events GROUP BY ip ORDER BY c DESC LIMIT 10").fetchall()],
    }
    con.close()
    return s

def add_honeytoken(token: str, label: str):
    con = _con()
    con.execute("INSERT OR IGNORE INTO honeytokens (token,label,created_at) VALUES (?,?,?)",
                (token, label, datetime.utcnow().isoformat()))
    con.commit(); con.close()

def trigger_honeytoken(token: str, triggered_by: str):
    con = _con()
    row = con.execute("SELECT triggered_by FROM honeytokens WHERE token=?", (token,)).fetchone()
    if row:
        tb = json.loads(row[0])
        tb.append({"ip": triggered_by, "ts": datetime.utcnow().isoformat()})
        con.execute("UPDATE honeytokens SET triggered=1,triggered_by=? WHERE token=?",
                    (json.dumps(tb), token))
        con.commit()
    con.close()

def _row(r) -> dict:
    d = dict(r)
    for k in ("data","geo","fingerprint","real_ips","tools","keylog","commands","credentials","triggered_by"):
        if k in d and isinstance(d[k], str):
            try: d[k] = json.loads(d[k])
            except: pass
    return d
