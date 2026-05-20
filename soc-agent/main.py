from fastapi import FastAPI

app = FastAPI(title="SOC Triage Agent")

@app.get("/health")
async def health():
    return {"status": "ok"}