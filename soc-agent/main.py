from fastapi import FastAPI
from splunk_mcp import run_query
from agent import triage
from report import generate_ir_report

app = FastAPI(title="SOC Triage Agent")

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
    result = await triage(alert)
    report = generate_ir_report(alert, result)
    return report