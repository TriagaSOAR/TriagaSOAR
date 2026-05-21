import json
import httpx
import os
from splunk_mcp import run_query

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
REASONER_MODEL = os.getenv("REASONER_MODEL", "qwen3:14b")
ROUTER_MODEL = os.getenv("ROUTER_MODEL", "qwen3:1.7b")

MAX_INVESTIGATION_DEPTH = 5


async def ollama_chat(model: str, messages: list, tools: list = None) -> dict:
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
    }
    if tools:
        payload["tools"] = tools

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()


async def route_alert(alert: dict) -> dict:
    """Use the small model to classify severity and alert type."""
    prompt = f"""You are a security alert classifier. Analyze this alert and respond with JSON only.

Alert: {json.dumps(alert)}

Respond with exactly this JSON structure:
{{
  "severity": "critical|high|medium|low",
  "alert_type": "brute_force|privilege_escalation|lateral_movement|anomaly|other",
  "should_investigate": true,
  "reason": "one sentence explanation"
}}"""

    result = await ollama_chat(ROUTER_MODEL, [{"role": "user", "content": prompt}])
    text = result["message"]["content"].strip()

    if "<think>" in text:
        text = text[text.rfind("</think>") + 8:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "severity": "medium",
            "alert_type": "other",
            "should_investigate": True,
            "reason": "Classification failed, defaulting to investigation",
        }


async def investigate(alert: dict, classification: dict) -> dict:
    """Primary agent — iterative pivot investigation with confidence scoring."""
    findings = []
    queries_run = []
    depth = 0
    index = alert.get("index", "main")

    initial_context = await run_query(
        f"index={index} | search {alert.get('search_terms', '*')} | head 20",
        earliest=alert.get("earliest", "-1h"),
        latest=alert.get("latest", "now"),
    )

    messages = [
        {
            "role": "system",
            "content": f"""You are an autonomous SOC analyst. Investigate security alerts by analyzing Splunk data.

Available index: {index}
Always use index={index} in your SPL queries.

For each step, respond with JSON:
{{
  "finding": "what you found",
  "confidence": 0.0-1.0,
  "next_spl": "SPL query to run next, or null if investigation complete",
  "pivot_reason": "why you're running this query",
  "complete": true/false
}}

Be precise. Confidence reflects evidence quality. Set complete=true only when you have enough to write a full report.""",
        },
        {
            "role": "user",
            "content": f"""Investigate this alert:
Alert: {json.dumps(alert)}
Classification: {json.dumps(classification)}
Initial data ({len(initial_context)} events): {json.dumps(initial_context[:5])}

Begin investigation.""",
        },
    ]

    while depth < MAX_INVESTIGATION_DEPTH:
        result = await ollama_chat(REASONER_MODEL, messages)
        text = result["message"]["content"].strip()

        if "<think>" in text:
            text = text[text.rfind("</think>") + 8:].strip()

        try:
            step = json.loads(text)
        except json.JSONDecodeError:
            break

        findings.append({
            "depth": depth,
            "finding": step.get("finding"),
            "confidence": step.get("confidence", 0.5),
            "pivot_reason": step.get("pivot_reason"),
        })

        messages.append({"role": "assistant", "content": text})

        if step.get("complete") or not step.get("next_spl"):
            break

        next_spl = step["next_spl"]
        queries_run.append(next_spl)
        query_results = await run_query(
            next_spl,
            earliest=alert.get("earliest", "-1h"),
            latest=alert.get("latest", "now"),
        )

        messages.append({
            "role": "user",
            "content": f"Query results ({len(query_results)} events): {json.dumps(query_results[:10])}. Continue investigation.",
        })

        depth += 1

    return {
        "findings": findings,
        "queries_run": queries_run,
        "depth_reached": depth,
        "avg_confidence": sum(f["confidence"] for f in findings) / len(findings) if findings else 0,
    }


async def adversarial_review(alert: dict, investigation: dict) -> dict:
    """Adversarial agent — critiques the primary investigation."""
    index = alert.get("index", "main")
    prompt = f"""You are a skeptical senior SOC analyst reviewing an investigation.

Alert: {json.dumps(alert)}
Investigation findings: {json.dumps(investigation["findings"])}
Queries run: {json.dumps(investigation["queries_run"])}

Available index: {index}
All suggested SPL queries must use index={index}.

Identify gaps, weak assumptions, or missed pivot points. Respond with JSON:
{{
  "verdict": "approved|needs_reinvestigation",
  "critique": "specific gaps or issues found",
  "missed_pivots": ["list of SPL queries that should have been run"],
  "confidence_adjustment": -0.2 to 0.0
}}"""

    result = await ollama_chat(REASONER_MODEL, [{"role": "user", "content": prompt}])
    text = result["message"]["content"].strip()

    if "<think>" in text:
        text = text[text.rfind("</think>") + 8:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "verdict": "approved",
            "critique": "Review parsing failed",
            "missed_pivots": [],
            "confidence_adjustment": 0.0,
        }


async def triage(alert: dict) -> dict:
    """Full triage pipeline: route → investigate → adversarial review."""

    classification = await route_alert(alert)

    if not classification.get("should_investigate"):
        return {
            "status": "skipped",
            "reason": classification.get("reason"),
            "classification": classification,
        }

    investigation = await investigate(alert, classification)
    review = await adversarial_review(alert, investigation)

    if review["verdict"] == "needs_reinvestigation" and review.get("missed_pivots"):
        extra_findings = []
        for spl in review["missed_pivots"][:2]:
            results = await run_query(spl, earliest=alert.get("earliest", "-1h"))
            extra_findings.append({
                "spl": spl,
                "result_count": len(results),
                "sample": results[:3] if results else [],
            })
        investigation["extra_findings"] = extra_findings

    final_confidence = max(
        0.0,
        investigation["avg_confidence"] + review.get("confidence_adjustment", 0.0),
    )

    return {
        "status": "complete",
        "classification": classification,
        "investigation": investigation,
        "review": review,
        "final_confidence": final_confidence,
    }