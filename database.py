import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("honeypot.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER,
            username TEXT,
            password TEXT,
            payload TEXT,
            severity TEXT DEFAULT 'low',
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(event_type: str, ip: str, port: int = None, username: str = None,
              password: str = None, payload: str = None, severity: str = "low", details: dict = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO events (timestamp, event_type, ip, port, username, password, payload, severity, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        event_type, ip, port, username, password, payload, severity,
        json.dumps(details or {})
    ))
    conn.commit()
    conn.close()

def get_events(limit: int = 100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    stats = {
        "total": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "ssh_attacks": conn.execute("SELECT COUNT(*) FROM events WHERE event_type='ssh_login'").fetchone()[0],
        "web_attacks": conn.execute("SELECT COUNT(*) FROM events WHERE event_type LIKE 'web_%'").fetchone()[0],
        "port_scans": conn.execute("SELECT COUNT(*) FROM events WHERE event_type='port_scan'").fetchone()[0],
        "unique_ips": conn.execute("SELECT COUNT(DISTINCT ip) FROM events").fetchone()[0],
        "top_ips": conn.execute(
            "SELECT ip, COUNT(*) as count FROM events GROUP BY ip ORDER BY count DESC LIMIT 5"
        ).fetchall(),
    }
    stats["top_ips"] = [{"ip": r[0], "count": r[1]} for r in stats["top_ips"]]
    conn.close()
    return stats
