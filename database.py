
import sqlite3
from datetime import datetime

DB_NAME = "analysis_history.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def initialize_database():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            ml_prediction TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            reasons TEXT,
            analyzed_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_analysis(result):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analysis
        (message, ml_prediction, risk_score,
         risk_level, reasons, analyzed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        result["message"],
        result["ml_prediction"],
        result["risk_score"],
        result["risk_level"],
        " | ".join(result["reasons"]),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_history():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM analysis
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return records
