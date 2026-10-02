"""
PhishLens - SQLite Local Database
Handles safe local logging of scan history and risk verdicts.
Complies with privacy policies: all logged targets have parameter values hashed.
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any
from config import DATABASE_PATH

def get_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it doesn't already exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target_sanitized TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                details_json TEXT
            )
        """)
        conn.commit()

def log_scan(
    scan_type: str,
    target_sanitized: str,
    verdict: str,
    risk_score: int,
    explanation: str,
    details: Dict[str, Any] = None
) -> int:
    """Logs a scan result into SQLite. Returns the new log ID."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_logs (timestamp, scan_type, target_sanitized, verdict, risk_score, explanation, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            scan_type,
            target_sanitized,
            verdict,
            risk_score,
            explanation,
            json.dumps(details or {})
        ))
        conn.commit()
        return cursor.lastrowid

def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieves recent scans for the dashboard history."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, scan_type, target_sanitized, verdict, risk_score, explanation
            FROM scan_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
