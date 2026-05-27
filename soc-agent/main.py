from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
import asyncio
from splunk_mcp import run_query
from agent import triage
from report import generate_ir_report
from database import init_db, save_report, correlate, get_all_cases, get_case
from blast_radius import estimate_blast_radius
from streaming import stream_investigation
from webhook import parse_splunk_webhook
from monitor import monitor_loop, get_saved_alerts, MONITOR_INTERVAL

monitor_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
    init_db()
    # Only start monitor if enabled
    import os
    if os.getenv("MONITOR_ENABLED", "false").lower() == "true":
        monitor_task = asyncio.create_task(monitor_loop(app))
        print("[monitor] Monitor started")
    yield
    if monitor_task:
        monitor_task.cancel()


app = FastAPI(title="SOC Triage Agent", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/test/splunk")
async def test_splunk():
    results = await run_query("index=* | head 5")
    return {"count": len(results), "sample": results[0] if results else None}


@app.post("/triage")
async def triage_alert(alert: dict):
    return await triage(alert)


@app.post("/investigate")
async def investigate_alert(alert: dict):
    prior_cases = correlate(alert)
    result = await triage(alert)
    report = generate_ir_report(alert, result)
    blast = await estimate_blast_radius(alert, report)
    report["blast_radius"] = blast
    if prior_cases:
        report["prior_cases"] = prior_cases
        report["repeated_attacker"] = True
    else:
        report["prior_cases"] = []
        report["repeated_attacker"] = False
    case_id = save_report(report, alert)
    report["case_id"] = case_id
    return report


@app.post("/investigate/stream")
async def investigate_stream(alert: dict):
    return StreamingResponse(
        stream_investigation(alert),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/webhook")
async def splunk_webhook(payload: dict, background_tasks: BackgroundTasks):
    alert = parse_splunk_webhook(payload)
    if not alert:
        raise HTTPException(status_code=400, detail="Could not parse webhook payload")
    background_tasks.add_task(run_webhook_investigation, alert)
    return {
        "status": "accepted",
        "alert_title": alert["title"],
        "search_terms": alert["search_terms"],
    }


async def run_webhook_investigation(alert: dict):
    try:
        prior_cases = correlate(alert)
        result = await triage(alert)
        report = generate_ir_report(alert, result)
        blast = await estimate_blast_radius(alert, report)
        report["blast_radius"] = blast
        report["prior_cases"] = prior_cases
        report["repeated_attacker"] = len(prior_cases) > 0
        report["triggered_by"] = "webhook"
        case_id = save_report(report, alert)
        report["case_id"] = case_id
    except Exception as e:
        print(f"Webhook investigation failed: {e}")


@app.get("/monitor/status")
async def monitor_status():
    return {
        "enabled": monitor_task is not None and not monitor_task.done(),
        "interval_seconds": MONITOR_INTERVAL,
    }


@app.get("/monitor/alerts")
async def list_monitor_alerts():
    """List all saved searches the monitor is watching."""
    alerts = await get_saved_alerts()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/cases")
async def list_cases():
    return get_all_cases()


@app.get("/cases/{report_id}")
async def get_case_by_id(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case