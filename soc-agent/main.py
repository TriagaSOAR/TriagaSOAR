from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from splunk_mcp import run_query
from agent import triage
from report import generate_ir_report
from database import init_db, save_report, correlate, get_all_cases, get_case
from blast_radius import estimate_blast_radius


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


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


@app.get("/cases")
async def list_cases():
    return get_all_cases()


@app.get("/cases/{report_id}")
async def get_case_by_id(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case