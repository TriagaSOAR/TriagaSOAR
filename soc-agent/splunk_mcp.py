import httpx
import os

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/mcp"

async def call_tool(name: str, arguments: dict) -> dict:
    async with httpx.AsyncClient(verify=VERIFY_SSL) as client:
        response = await client.post(
            BASE_URL,
            headers={
                "Authorization": f"Bearer {SPLUNK_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()

async def run_query(spl: str, earliest: str = "-24h", latest: str = "now", limit: int = 100) -> list[dict]:
    result = await call_tool("splunk_run_query", {
        "query": spl,
        "earliest_time": earliest,
        "latest_time": latest,
        "row_limit": limit,
    })
    content = result.get("result", {}).get("structuredContent", {})
    return content.get("results", [])

async def get_metadata(type: str, index: str = "*") -> list[dict]:
    result = await call_tool("splunk_get_metadata", {"type": type, "index": index})
    content = result.get("result", {}).get("structuredContent", {})
    return content.get("results", [])