import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinelmesh.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the SQLite database and create the events table if it does not exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            decision TEXT NOT NULL,
            reasons TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_event(session_id: str, action: str, resource: str, risk_score: int, decision: str, reasons: List[str]) -> int:
    """Log a security event to the SQLite database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reasons_str = json.dumps(reasons) if isinstance(reasons, list) else str(reasons)
    
    cursor.execute("""
        INSERT INTO events (timestamp, session_id, action, resource, risk_score, decision, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, session_id, action, resource, risk_score, decision, reasons_str))
    
    conn.commit()
    event_id = cursor.lastrowid
    conn.close()
    return event_id

def get_events(limit: int = 50, exclude_tests: bool = True) -> List[Dict[str, Any]]:
    """Retrieve historical security events from the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    if exclude_tests:
        cursor.execute("""
            SELECT id, timestamp, session_id, action, resource, risk_score, decision, reasons
            FROM events
            WHERE session_id NOT LIKE 'unittest%' AND session_id NOT LIKE 'test_%'
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
    else:
        cursor.execute("""
            SELECT id, timestamp, session_id, action, resource, risk_score, decision, reasons
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        reasons_raw = row["reasons"]
        try:
            parsed_reasons = json.loads(reasons_raw)
        except Exception:
            parsed_reasons = [reasons_raw]
            
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "session_id": row["session_id"],
            "action": row["action"],
            "resource": row["resource"],
            "risk_score": row["risk_score"],
            "decision": row["decision"],
            "reasons": parsed_reasons
        })
    return events

def clear_events():
    """Clear all events from the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events")
    conn.commit()
    conn.close()
