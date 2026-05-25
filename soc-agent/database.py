import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", "/app/data/cases.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   TEXT UNIQUE NOT NULL,
            created_at  TEXT NOT NULL,
            title       TEXT,
            severity    TEXT,
            alert_type  TEXT,
            confidence  REAL,
            kill_chain  TEXT,
            summary     TEXT,
            full_report TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     INTEGER NOT NULL,
            type        TEXT NOT NULL,
            value       TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );

        CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
        CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities(type, value);
    """)
    conn.commit()
    conn.close()


def save_report(report: dict, alert: dict) -> int:
    """Save an IR report to the database and extract entities."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            INSERT OR REPLACE INTO cases
                (report_id, created_at, title, severity, alert_type, confidence, kill_chain, summary, full_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report["report_id"],
            report["generated_at"],
            alert.get("title"),
            report.get("severity"),
            report.get("alert_type"),
            report.get("final_confidence"),
            report.get("kill_chain_summary"),
            report.get("summary"),
            json.dumps(report),
        ))
        case_id = cursor.lastrowid

        # Extract and store entities for correlation
        entities = extract_entities(alert, report)
        for entity_type, value in entities:
            conn.execute(
                "INSERT INTO entities (case_id, type, value) VALUES (?, ?, ?)",
                (case_id, entity_type, value),
            )

        conn.commit()
        return case_id
    finally:
        conn.close()


def extract_entities(alert: dict, report: dict) -> list[tuple]:
    """Pull IPs, users, and hosts from alert and findings for correlation."""
    import re
    entities = []

    # From alert search terms
    search_terms = alert.get("search_terms", "")

    # Extract IPs
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", search_terms)
    for ip in ips:
        entities.append(("ip", ip))

    # From findings text
    for finding in report.get("findings", []):
        text = finding.get("finding", "")
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        for ip in ips:
            entities.append(("ip", ip))

        # Extract usernames (patterns like "user 'inf'" or "for user inf")
        users = re.findall(r"user['\s]+([a-zA-Z0-9_-]+)", text)
        for user in users:
            if user not in ("root", "the", "a", "an"):
                entities.append(("user", user))

    # Deduplicate
    return list(set(entities))


def correlate(alert: dict) -> list[dict]:
    """Check if any entities in this alert appeared in prior cases."""
    import re
    search_terms = alert.get("search_terms", "")
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", search_terms)

    if not ips:
        return []

    conn = get_connection()
    try:
        prior_cases = []
        for ip in ips:
            rows = conn.execute("""
                SELECT c.report_id, c.created_at, c.title, c.severity, c.kill_chain
                FROM cases c
                JOIN entities e ON e.case_id = c.id
                WHERE e.type = 'ip' AND e.value = ?
                ORDER BY c.created_at DESC
                LIMIT 5
            """, (ip,)).fetchall()

            for row in rows:
                prior_cases.append({
                    "report_id": row["report_id"],
                    "created_at": row["created_at"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "kill_chain": row["kill_chain"],
                    "matched_entity": {"type": "ip", "value": ip},
                })

        return prior_cases
    finally:
        conn.close()


def get_all_cases() -> list[dict]:
    """Return all cases for the case file browser."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT report_id, created_at, title, severity, alert_type, confidence, kill_chain, summary
            FROM cases
            ORDER BY created_at DESC
        """).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_case(report_id: str) -> dict | None:
    """Return full report for a single case."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT full_report FROM cases WHERE report_id = ?", (report_id,)
        ).fetchone()
        return json.loads(row["full_report"]) if row else None
    finally:
        conn.close()