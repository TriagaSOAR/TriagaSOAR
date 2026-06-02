import json
import os
from splunk_mcp import run_query
from llm_client import chat, get_reasoner_model, get_router_model

MAX_INVESTIGATION_DEPTH = 5


async def ollama_chat(model: str, messages: list, tools: list = None) -> dict:
    """Backwards-compatible wrapper — delegates to llm_client."""
    return await chat(model, messages)


async def route_alert(alert: dict) -> dict:
    """Use the small/router model to classify severity and alert type."""
    prompt = f"""You are a security alert classifier. Analyze this alert and respond with JSON only.

Alert: {json.dumps(alert)}

Respond with exactly this JSON structure:
{{
  "severity": "critical|high|medium|low",
  "alert_type": "brute_force|privilege_escalation|lateral_movement|anomaly|other",
  "should_investigate": true,
  "reason": "one sentence explanation"
}}"""

    result = await chat(get_router_model(), [{"role": "user", "content": prompt}])
    text = result["message"]["content"].strip()

    if "<think>" in text:
        text = text[text.rfind("</think>") + 8:].strip()

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        text = text[start:end]

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
Sourcetype: linux_secure (raw syslog — fields like src_ip, user, status are NOT extracted)
Always use index={index} in your SPL queries.
Search raw text using quotes: index={index} "search term" rather than field=value syntax.
Example good query: index=main "Failed password" "10.10.10.99"
Example bad query: index=main src_ip=10.10.10.99 status=failed

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
        result = await chat(get_reasoner_model(), messages)
        text = result["message"]["content"].strip()

        if "<think>" in text:
            text = text[text.rfind("</think>") + 8:].strip()
        if "```" in text:
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            text = text[start:end]

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
        if not next_spl.strip().startswith("index="):
            messages.append({
                "role": "user",
                "content": "Invalid SPL query. Your next_spl must start with 'index='. Try again.",
            })
            depth += 1
            continue

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
Sourcetype: linux_secure (raw syslog — fields like src_ip, user, status are NOT extracted)
All suggested SPL queries must use index={index}.
Search raw text using quotes.

Identify gaps, weak assumptions, or missed pivot points. Respond with JSON:
{{
  "verdict": "approved|needs_reinvestigation",
  "critique": "specific gaps or issues found",
  "missed_pivots": ["list of SPL queries that should have been run"],
  "confidence_adjustment": -0.2 to 0.0
}}"""

    result = await chat(get_reasoner_model(), [{"role": "user", "content": prompt}])
    text = result["message"]["content"].strip()

    if "<think>" in text:
        text = text[text.rfind("</think>") + 8:].strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        text = text[start:end]

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

    investigation_result = await investigate(alert, classification)
    review = await adversarial_review(alert, investigation_result)

    if review["verdict"] == "needs_reinvestigation" and review.get("missed_pivots"):
        extra_findings = []
        for spl in review["missed_pivots"][:2]:
            if not spl.strip().startswith("index="):
                continue
            results = await run_query(spl, earliest=alert.get("earliest", "-1h"))
            extra_findings.append({
                "spl": spl,
                "result_count": len(results),
                "sample": results[:3] if results else [],
            })
        investigation_result["extra_findings"] = extra_findings

    final_confidence = max(
        0.0,
        investigation_result["avg_confidence"] + review.get("confidence_adjustment", 0.0),
    )

    return {
        "status": "complete",
        "classification": classification,
        "investigation": investigation_result,
        "review": review,
        "final_confidence": final_confidence,
    }