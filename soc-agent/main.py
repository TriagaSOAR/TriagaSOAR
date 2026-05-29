from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse
from contextlib import asynccontextmanager
import asyncio
import os
import json
from splunk_mcp import run_query, call_tool
from agent import triage, ollama_chat
from report import generate_ir_report
from database import init_db, save_report, correlate, get_all_cases, get_case, get_connection
from blast_radius import estimate_blast_radius
from streaming import stream_investigation
from webhook import parse_splunk_webhook
from monitor import monitor_loop, get_saved_alerts, MONITOR_INTERVAL
from threat_intel import enrich_ips, lookup_ip

monitor_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
    init_db()
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
    attacker_ips = blast.get("attacker_ips", [])
    report["threat_intel"] = await enrich_ips(attacker_ips) if attacker_ips else {}
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
        attacker_ips = blast.get("attacker_ips", [])
        report["threat_intel"] = await enrich_ips(attacker_ips) if attacker_ips else {}
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
    alerts = await get_saved_alerts()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/threatintel/{ip}")
async def threat_intel_lookup(ip: str):
    return await lookup_ip(ip)


@app.post("/splunk/query")
async def natural_language_query(body: dict):
    nl_query = body.get("query", "")
    index = body.get("index", "main")
    earliest = body.get("earliest", "-1h")
    latest = body.get("latest", "now")

    if not nl_query:
        raise HTTPException(status_code=400, detail="Query is required")

    prompt = f"""You are a Splunk SPL expert. Convert this natural language query to a valid SPL search query.

Natural language query: {nl_query}
Available index: {index}
Sourcetype available: linux_secure (raw syslog auth logs)

Rules:
- Always start with: index={index}
- Use raw text search with quotes since fields are not extracted
- Keep it simple and functional
- Return ONLY the SPL query, nothing else, no explanation, no markdown

SPL query:"""

    result = await ollama_chat(
        os.getenv("REASONER_MODEL", "qwen3:14b"),
        [{"role": "user", "content": prompt}]
    )
    spl = result["message"]["content"].strip()

    if "<think>" in spl:
        spl = spl[spl.rfind("</think>") + 8:].strip()
    if "```" in spl:
        lines = spl.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        spl = "\n".join(lines).strip()

    if not spl.startswith("index="):
        raise HTTPException(status_code=422, detail=f"Generated invalid SPL: {spl}")

    results = await run_query(spl, earliest=earliest, latest=latest, limit=50)

    return {
        "natural_language": nl_query,
        "generated_spl": spl,
        "result_count": len(results),
        "results": results,
    }


@app.get("/splunk/health")
async def splunk_health():
    info_task = call_tool("splunk_get_info", {})
    indexes_task = call_tool("splunk_get_indexes", {"row_limit": 50})
    metadata_task = call_tool("splunk_get_metadata", {"type": "sourcetypes", "index": "*"})

    info_result, indexes_result, metadata_result = await asyncio.gather(
        info_task, indexes_task, metadata_task, return_exceptions=True
    )

    instance_info = {}
    if not isinstance(info_result, Exception):
        content = info_result.get("result", {}).get("structuredContent", {})
        results = content.get("results", [])
        if results:
            instance_info = results[0]

    indexes = []
    if not isinstance(indexes_result, Exception):
        content = indexes_result.get("result", {}).get("structuredContent", {})
        indexes = content.get("results", [])

    sourcetypes = []
    if not isinstance(metadata_result, Exception):
        content = metadata_result.get("result", {}).get("structuredContent", {})
        sourcetypes = content.get("results", [])

    return {
        "instance": instance_info,
        "indexes": indexes,
        "sourcetypes": sourcetypes,
    }


@app.get("/attackers/{ip}")
async def attacker_profile(ip: str):
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT c.report_id, c.created_at, c.title, c.severity,
                   c.alert_type, c.confidence, c.kill_chain, c.full_report
            FROM cases c
            JOIN entities e ON e.case_id = c.id
            WHERE e.type = 'ip' AND e.value = ?
            ORDER BY c.created_at ASC
        """, (ip,)).fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail=f"No cases found for IP {ip}")

        cases = []
        all_techniques = {}
        all_users = set()
        total_events = 0

        for row in rows:
            report = json.loads(row["full_report"])
            blast = report.get("blast_radius", {})
            total_events += sum(
                int(e.get("event_count", 0) or 0)
                for e in blast.get("related_events", [])
                if e.get("entity") == ip
            )
            for u in blast.get("compromised_users", []):
                all_users.add(u)
            for t in report.get("mitre_techniques", []):
                tid = t["technique_id"]
                if tid not in all_techniques:
                    all_techniques[tid] = {**t, "count": 0}
                all_techniques[tid]["count"] += 1

            cases.append({
                "report_id": row["report_id"],
                "created_at": row["created_at"],
                "title": row["title"],
                "severity": row["severity"],
                "alert_type": row["alert_type"],
                "confidence": row["confidence"],
                "kill_chain": row["kill_chain"],
            })

        return {
            "ip": ip,
            "first_seen": cases[0]["created_at"],
            "last_seen": cases[-1]["created_at"],
            "total_incidents": len(cases),
            "total_events": total_events,
            "compromised_users": list(all_users),
            "techniques": sorted(all_techniques.values(), key=lambda t: t["count"], reverse=True),
            "cases": cases,
        }
    finally:
        conn.close()


@app.get("/cases/{report_id}/navigator")
async def mitre_navigator_export(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    techniques = case.get("mitre_techniques", [])
    confidence = case.get("final_confidence", 0)

    layer = {
        "name": f"SOC Triage — {case.get('alert', {}).get('title', report_id)}",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Auto-generated by Splunk SOC Triage Agent. Report: {report_id}. Confidence: {round(confidence * 100)}%",
        "filters": {"platforms": ["Linux", "Windows", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [{"label": "Detected technique", "color": "#ff6666"}],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#16161f",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }

    for t in techniques:
        layer["techniques"].append({
            "techniqueID": t.get("technique_id", ""),
            "tactic": t.get("tactic", "").lower().replace(" ", "-"),
            "score": round(confidence * 100),
            "color": "",
            "comment": t.get("technique_name", ""),
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": True,
        })

    return JSONResponse(
        content=layer,
        headers={
            "Content-Disposition": f"attachment; filename=navigator_{report_id}.json",
            "Content-Type": "application/json",
        }
    )


@app.get("/cases")
async def list_cases():
    return get_all_cases()


@app.get("/cases/{report_id}")
async def get_case_by_id(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case