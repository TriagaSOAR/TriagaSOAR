import asyncio
import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from splunk_mcp import call_tool, run_query
from database import get_connection

MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL_SECONDS", "60"))
COOLDOWN_MINUTES = int(os.getenv("MONITOR_COOLDOWN_MINUTES", "5"))


def init_monitor_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitor_state (
            search_name TEXT PRIMARY KEY,
            last_investigated TEXT,
            last_result_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def get_last_investigated(search_name: str) -> datetime | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT last_investigated FROM monitor_state WHERE search_name = ?",
        (search_name,)
    ).fetchone()
    conn.close()
    if row and row[0]:
        return datetime.fromisoformat(row[0])
    return None


def update_monitor_state(search_name: str, result_count: int):
    conn = get_connection()
    conn.execute("""
        INSERT INTO monitor_state (search_name, last_investigated, last_result_count)
        VALUES (?, ?, ?)
        ON CONFLICT(search_name) DO UPDATE SET
            last_investigated = excluded.last_investigated,
            last_result_count = excluded.last_result_count
    """, (search_name, datetime.now(timezone.utc).isoformat(), result_count))
    conn.commit()
    conn.close()


def is_on_cooldown(search_name: str) -> bool:
    last = get_last_investigated(search_name)
    if not last:
        return False
    cooldown = timedelta(minutes=COOLDOWN_MINUTES)
    return datetime.now(timezone.utc) - last < cooldown


async def get_saved_alerts() -> list[dict]:
    """Fetch all saved searches with alerting enabled via Splunk MCP."""
    try:
        result = await call_tool("splunk_get_knowledge_objects", {
            "type": "saved_searches",
            "row_limit": 100,
        })
        content = result.get("result", {}).get("structuredContent", {})
        searches = content.get("results", [])

        # Filter to only those with alert actions enabled
        alerts = []
        for s in searches:
            name = s.get("title") or s.get("name", "")
            if name and not name.startswith("_"):  # skip internal searches
                alerts.append({
                    "name": name,
                    "search": s.get("search", ""),
                    "app": s.get("eai:acl.app", "search"),
                })
        return alerts
    except Exception as e:
        print(f"[monitor] Failed to fetch saved searches: {e}")
        return []


async def check_alert(alert: dict) -> int:
    """Run the saved search and return result count."""
    try:
        search = alert.get("search", "")
        if not search or not search.strip().startswith("search") and not search.strip().startswith("index"):
            return 0

        # Clean up the search string
        spl = search.strip()
        if spl.startswith("search "):
            spl = spl[7:]

        results = await run_query(spl, earliest="-5m", latest="now", limit=10)
        return len(results)
    except Exception as e:
        print(f"[monitor] Error checking alert '{alert.get('name')}': {e}")
        return 0


async def monitor_loop(app):
    """Main monitoring loop — runs as a background task."""
    from agent import triage
    from report import generate_ir_report
    from database import save_report, correlate
    from blast_radius import estimate_blast_radius

    init_monitor_db()
    print(f"[monitor] Starting — polling every {MONITOR_INTERVAL}s, cooldown {COOLDOWN_MINUTES}m")

    while True:
        try:
            alerts = await get_saved_alerts()
            print(f"[monitor] Found {len(alerts)} saved searches")

            for alert in alerts:
                name = alert["name"]

                if is_on_cooldown(name):
                    continue

                count = await check_alert(alert)
                if count == 0:
                    continue

                print(f"[monitor] Alert '{name}' has {count} results — triggering investigation")
                update_monitor_state(name, count)

                # Build investigation alert
                investigation_alert = {
                    "title": f"[AUTO] {name}",
                    "search_terms": alert.get("search", "*")[:200],
                    "index": "main",
                    "earliest": "-15m",
                    "latest": "now",
                    "triggered_by": "monitor",
                }

                try:
                    prior_cases = correlate(investigation_alert)
                    result = await triage(investigation_alert)
                    report = generate_ir_report(investigation_alert, result)
                    blast = await estimate_blast_radius(investigation_alert, report)
                    report["blast_radius"] = blast
                    report["prior_cases"] = prior_cases
                    report["repeated_attacker"] = len(prior_cases) > 0
                    report["triggered_by"] = "monitor"
                    save_report(report, investigation_alert)
                    print(f"[monitor] Investigation complete: {report['report_id']}")
                except Exception as e:
                    print(f"[monitor] Investigation failed for '{name}': {e}")

        except Exception as e:
            print(f"[monitor] Loop error: {e}")

        await asyncio.sleep(MONITOR_INTERVAL)