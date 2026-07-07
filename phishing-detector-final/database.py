import sqlite3
from datetime import datetime

DB_PATH = "history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mode TEXT,
            input_summary TEXT,
            score INTEGER,
            classification TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(mode, input_summary, score, classification):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (mode, input_summary, score, classification, timestamp) VALUES (?, ?, ?, ?, ?)",
        (mode, input_summary[:200], score, classification, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_history(limit=20):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT mode, input_summary, score, classification, timestamp FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [
        {"mode": r[0], "input": r[1], "score": r[2], "classification": r[3], "timestamp": r[4]}
        for r in rows
    ]
