from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse, Response
from contextlib import asynccontextmanager
import asyncio
import os
import json
import tempfile
import httpx
from splunk_mcp import run_query, call_tool
from agent import triage, ollama_chat
from report import generate_ir_report
from database import init_db, save_report, correlate, get_all_cases, get_case, get_connection, set_verdict, get_stats
from blast_radius import estimate_blast_radius
from streaming import stream_investigation
from webhook import parse_splunk_webhook
from monitor import monitor_loop, get_saved_alerts, MONITOR_INTERVAL
from threat_intel import enrich_ips, lookup_ip
from patterns import PATTERNS

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


@app.get("/patterns")
async def list_patterns():
    return PATTERNS


@app.get("/patterns/{pattern_id}")
async def get_pattern(pattern_id: str):
    pattern = next((p for p in PATTERNS if p["id"] == pattern_id), None)
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return pattern


@app.patch("/cases/{report_id}/verdict")
async def update_verdict(report_id: str, body: dict):
    verdict = body.get("verdict")
    if verdict not in ("confirmed", "false_positive", None):
        raise HTTPException(status_code=400, detail="verdict must be 'confirmed', 'false_positive', or null")
    success = set_verdict(report_id, verdict)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"report_id": report_id, "verdict": verdict}


@app.get("/stats")
async def statistics():
    return get_stats()


@app.get("/cases/compare")
async def compare_cases(a: str, b: str):
    case_a = get_case(a)
    case_b = get_case(b)
    if not case_a:
        raise HTTPException(status_code=404, detail=f"Case {a} not found")
    if not case_b:
        raise HTTPException(status_code=404, detail=f"Case {b} not found")

    techs_a = {t["technique_id"] for t in case_a.get("mitre_techniques", [])}
    techs_b = {t["technique_id"] for t in case_b.get("mitre_techniques", [])}

    return {
        "case_a": {
            "report_id": case_a.get("report_id"),
            "title": case_a.get("alert", {}).get("title"),
            "severity": case_a.get("severity"),
            "confidence": case_a.get("final_confidence"),
            "summary": case_a.get("summary"),
            "mitre_techniques": case_a.get("mitre_techniques", []),
            "kill_chain": case_a.get("kill_chain_summary"),
            "findings_count": len(case_a.get("findings", [])),
            "blast_radius": case_a.get("blast_radius", {}),
            "adversarial_review": case_a.get("adversarial_review", {}),
            "generated_at": case_a.get("generated_at"),
            "verdict": case_a.get("verdict"),
        },
        "case_b": {
            "report_id": case_b.get("report_id"),
            "title": case_b.get("alert", {}).get("title"),
            "severity": case_b.get("severity"),
            "confidence": case_b.get("final_confidence"),
            "summary": case_b.get("summary"),
            "mitre_techniques": case_b.get("mitre_techniques", []),
            "kill_chain": case_b.get("kill_chain_summary"),
            "findings_count": len(case_b.get("findings", [])),
            "blast_radius": case_b.get("blast_radius", {}),
            "adversarial_review": case_b.get("adversarial_review", {}),
            "generated_at": case_b.get("generated_at"),
            "verdict": case_b.get("verdict"),
        },
        "diff": {
            "techniques_only_in_a": list(techs_a - techs_b),
            "techniques_only_in_b": list(techs_b - techs_a),
            "techniques_in_both": list(techs_a & techs_b),
            "severity_match": case_a.get("severity") == case_b.get("severity"),
            "confidence_delta": round(
                (case_a.get("final_confidence", 0) - case_b.get("final_confidence", 0)) * 100, 1
            ),
        },
    }


@app.post("/splunk/saved-searches")
async def create_saved_search(body: dict):
    name = body.get("name", "")
    spl = body.get("spl", "")
    description = body.get("description", "")

    if not name or not spl:
        raise HTTPException(status_code=400, detail="name and spl are required")

    splunk_host = os.getenv("SPLUNK_HOST", "localhost")
    splunk_port = os.getenv("SPLUNK_PORT", "8089")
    splunk_token = os.getenv("SPLUNK_TOKEN", "")

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(
                f"https://{splunk_host}:{splunk_port}/servicesNS/nobody/search/saved/searches",
                headers={"Authorization": f"Bearer {splunk_token}"},
                data={"name": name, "search": spl, "description": description},
            )
            if response.status_code not in (200, 201):
                raise HTTPException(
                    status_code=502,
                    detail=f"Splunk returned {response.status_code}: {response.text[:200]}"
                )
            return {"status": "created", "name": name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create saved search: {str(e)}")


@app.get("/cases/{report_id}/navigator")
async def mitre_navigator_export(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    techniques = case.get("mitre_techniques", [])
    confidence = case.get("final_confidence", 0)

    layer = {
        "name": f"SOC Triage — {case.get('alert', {}).get('title', report_id)}",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated by Splunk SOC Triage Agent. Report: {report_id}. Confidence: {round(confidence * 100)}%",
        "filters": {"platforms": ["Linux", "Windows", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Detected technique", "color": "#ff6666"}],
        "metadata": [], "links": [],
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
            "metadata": [], "links": [],
            "showSubtechniques": True,
        })

    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f"attachment; filename=navigator_{report_id}.json", "Content-Type": "application/json"}
    )


@app.get("/cases/{report_id}/pdf")
async def export_pdf(report_id: str):
    from weasyprint import HTML

    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    confidence = case.get("final_confidence", 0)
    severity = case.get("severity", "unknown")
    alert = case.get("alert", {})
    findings = case.get("findings", [])
    mitre = case.get("mitre_techniques", [])
    blast = case.get("blast_radius", {})
    recommendations = case.get("recommendations", [])
    review = case.get("adversarial_review", {})
    queries = case.get("queries_run", [])
    threat_intel = case.get("threat_intel", {})

    severity_colors = {"critical": "#ff4d6a", "high": "#ff8c42", "medium": "#ffd166", "low": "#06d6a0"}
    color = severity_colors.get(severity, "#7c7c7c")

    kill_chain_html = ""
    if mitre:
        techs = " → ".join(
            f'<span style="color:#7b61ff;font-family:monospace">{t["technique_id"]}</span> <span style="color:#ccc">{t["technique_name"]}</span>'
            for t in mitre
        )
        kill_chain_html = f'<div style="margin-bottom:8px">{techs}</div>'

    findings_html = "".join(f"""
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #2a2a3a">
            <span style="color:#c0c0d0;flex:1">{f.get('finding','')}</span>
            <span style="color:#ff8c42;font-family:monospace;margin-left:16px">{round(f.get('confidence',0)*100)}%</span>
        </div>
    """ for f in findings)

    blast_ips = ", ".join(blast.get("attacker_ips", [])) or "None"
    blast_users = ", ".join(blast.get("compromised_users", [])) or "None"
    blast_hosts = ", ".join(blast.get("affected_hosts", [])) or "None"
    recommendations_html = "".join(f'<div style="padding:4px 0;color:#c0c0d0">→ {r}</div>' for r in recommendations)
    queries_html = "".join(f'<div style="font-family:monospace;font-size:11px;color:#7b61ff;padding:4px 8px;background:#16161f;border-radius:4px;margin-bottom:4px">{q}</div>' for q in queries)

    threat_html = ""
    for ip, intel in threat_intel.items():
        if intel.get("available"):
            threat_html += f'<div style="padding:8px;background:#16161f;border-radius:6px;margin-bottom:8px"><span style="font-family:monospace;color:#ff4d6a">{ip}</span><span style="margin-left:12px;color:#888">Abuse: {intel.get("abuse_confidence_score")}% · {intel.get("country_code")} · {intel.get("isp")} · {intel.get("threat_level","").upper()}</span></div>'
        else:
            threat_html += f'<div style="padding:8px;background:#16161f;border-radius:6px;margin-bottom:8px"><span style="font-family:monospace;color:#ff4d6a">{ip}</span><span style="margin-left:12px;color:#888">{intel.get("message","")}</span></div>'

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
        body {{ font-family: -apple-system, sans-serif; background: #0d0d14; color: #e0e0f0; margin: 0; padding: 40px; }}
        h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 4px 0; }}
        h2 {{ font-size: 13px; font-weight: 600; color: #888; letter-spacing: 0.08em; text-transform: uppercase; margin: 0 0 12px 0; border-bottom: 1px solid #2a2a3a; padding-bottom: 6px; }}
        .card {{ background: #13131e; border: 1px solid #2a2a3a; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; border: 1px solid {color}44; background: {color}22; color: {color}; }}
        .meta {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .confidence {{ font-family: monospace; font-size: 36px; font-weight: 700; color: {color}; }}
    </style></head><body>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px">
        <div>
            <div style="font-family:monospace;font-size:11px;color:#888;margin-bottom:6px">SOC TRIAGE · {case.get('report_id','')}</div>
            <h1>{alert.get('title','Unknown Alert')}</h1>
            <div class="meta">{alert.get('index','')} · {alert.get('time_range','')} · {case.get('generated_at','')}</div>
            <div style="margin-top:10px"><span class="badge">{severity}</span></div>
        </div>
        <div style="text-align:right">
            <div class="confidence">{round(confidence*100)}%</div>
            <div style="font-size:11px;color:#888">confidence</div>
        </div>
    </div>
    <div class="card"><h2>Summary</h2><p style="color:#c0c0d0;line-height:1.7;margin:0">{case.get('summary','')}</p></div>
    <div class="card"><h2>MITRE ATT&amp;CK Kill Chain</h2>{kill_chain_html if kill_chain_html else '<span style="color:#888">No techniques mapped</span>'}</div>
    <div class="card"><h2>Investigation Findings</h2>{findings_html if findings_html else '<span style="color:#888">No findings</span>'}</div>
    <div class="card"><h2>Blast Radius</h2>
        <div style="color:#c0c0d0;margin-bottom:10px">{blast.get('risk_summary','')}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">ATTACKER IPS</div><div style="color:#ff4d6a;font-family:monospace">{blast_ips}</div></div>
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">COMPROMISED USERS</div><div style="color:#ff8c42;font-family:monospace">{blast_users}</div></div>
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">AFFECTED HOSTS</div><div style="color:#ffd166;font-family:monospace">{blast_hosts}</div></div>
        </div>
    </div>
    {f'<div class="card"><h2>Threat Intelligence</h2>{threat_html}</div>' if threat_html else ''}
    <div class="card"><h2>Adversarial Review</h2>
        <div style="margin-bottom:8px"><span style="font-family:monospace;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;background:{'rgba(6,214,160,0.1)' if review.get('verdict')=='approved' else 'rgba(255,209,102,0.1)'};color:{'#06d6a0' if review.get('verdict')=='approved' else '#ffd166'};border:1px solid {'rgba(6,214,160,0.3)' if review.get('verdict')=='approved' else 'rgba(255,209,102,0.3)'};text-transform:uppercase">{review.get('verdict','')}</span></div>
        <p style="color:#c0c0d0;line-height:1.7;margin:0">{review.get('critique','')}</p>
    </div>
    <div class="card"><h2>Recommendations</h2>{recommendations_html if recommendations_html else '<span style="color:#888">None</span>'}</div>
    <div class="card"><h2>SPL Queries Executed</h2>{queries_html if queries_html else '<span style="color:#888">None</span>'}</div>
    <div style="text-align:center;color:#444;font-size:11px;margin-top:32px;font-family:monospace">Generated by Splunk SOC Triage Agent · {case.get('report_id','')}</div>
    </body></html>"""

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        HTML(string=html).write_pdf(f.name)
        pdf_path = f.name

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    os.unlink(pdf_path)

    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=IR_{report_id}.pdf"})


@app.get("/cases")
async def list_cases():
    return get_all_cases()


@app.get("/cases/{report_id}")
async def get_case_by_id(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case