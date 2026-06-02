import json
import asyncio
from typing import AsyncGenerator
from agent import route_alert
from llm_client import chat, get_reasoner_model
from splunk_mcp import run_query
from report import generate_ir_report
from database import save_report, correlate
from blast_radius import estimate_blast_radius
from threat_intel import enrich_ips
import os

MAX_INVESTIGATION_DEPTH = 5


def sse_event(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


async def stream_investigation(alert: dict) -> AsyncGenerator[str, None]:
    index = alert.get("index", "main")

    yield sse_event("status", {"stage": "routing", "message": "Classifying alert..."})
    classification = await route_alert(alert)
    yield sse_event("classification", classification)

    if not classification.get("should_investigate"):
        yield sse_event("complete", {"status": "skipped", "reason": classification.get("reason")})
        return

    yield sse_event("status", {"stage": "investigating", "message": "Starting investigation loop..."})

    initial_context = await run_query(
        f"index={index} | search {alert.get('search_terms', '*')} | head 20",
        earliest=alert.get("earliest", "-1h"),
        latest=alert.get("latest", "now"),
    )

    yield sse_event("status", {"stage": "investigating", "message": f"Initial query returned {len(initial_context)} events"})

    findings = []
    queries_run = []
    depth = 0

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
        yield sse_event("status", {"stage": "investigating", "message": f"Investigation step {depth + 1}/{MAX_INVESTIGATION_DEPTH}..."})

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

        finding = {
            "depth": depth,
            "finding": step.get("finding"),
            "confidence": step.get("confidence", 0.5),
            "pivot_reason": step.get("pivot_reason"),
        }
        findings.append(finding)
        yield sse_event("finding", finding)
        messages.append({"role": "assistant", "content": text})

        if step.get("complete") or not step.get("next_spl"):
            break

        next_spl = step["next_spl"]
        if not next_spl.strip().startswith("index="):
            messages.append({"role": "user", "content": "Invalid SPL query. Your next_spl must start with 'index='. Try again."})
            depth += 1
            continue

        queries_run.append(next_spl)
        yield sse_event("query", {"spl": next_spl, "depth": depth})

        query_results = await run_query(next_spl, earliest=alert.get("earliest", "-1h"), latest=alert.get("latest", "now"))
        yield sse_event("query_result", {"spl": next_spl, "count": len(query_results)})

        messages.append({"role": "user", "content": f"Query results ({len(query_results)} events): {json.dumps(query_results[:10])}. Continue investigation."})
        depth += 1

    investigation = {
        "findings": findings,
        "queries_run": queries_run,
        "depth_reached": depth,
        "avg_confidence": sum(f["confidence"] for f in findings) / len(findings) if findings else 0,
    }

    yield sse_event("status", {"stage": "reviewing", "message": "Adversarial agent reviewing findings..."})

    adv_prompt = f"""You are a skeptical senior SOC analyst reviewing an investigation.

Alert: {json.dumps(alert)}
Investigation findings: {json.dumps(findings)}
Queries run: {json.dumps(queries_run)}

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

    adv_result = await chat(get_reasoner_model(), [{"role": "user", "content": adv_prompt}])
    adv_text = adv_result["message"]["content"].strip()

    if "<think>" in adv_text:
        adv_text = adv_text[adv_text.rfind("</think>") + 8:].strip()
    if "```" in adv_text:
        lines = adv_text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        adv_text = "\n".join(lines).strip()
    start = adv_text.find("{")
    end = adv_text.rfind("}") + 1
    if start != -1 and end > start:
        adv_text = adv_text[start:end]

    try:
        review = json.loads(adv_text)
    except json.JSONDecodeError:
        review = {"verdict": "approved", "critique": "Review parsing failed", "missed_pivots": [], "confidence_adjustment": 0.0}

    yield sse_event("review", review)

    if review["verdict"] == "needs_reinvestigation" and review.get("missed_pivots"):
        yield sse_event("status", {"stage": "reinvestigating", "message": "Running missed pivot queries..."})
        extra_findings = []
        for spl in review["missed_pivots"][:2]:
            if not spl.strip().startswith("index="):
                continue
            results = await run_query(spl, earliest=alert.get("earliest", "-1h"))
            extra_findings.append({"spl": spl, "result_count": len(results), "sample": results[:3] if results else []})
            yield sse_event("query_result", {"spl": spl, "count": len(results)})
        investigation["extra_findings"] = extra_findings

    final_confidence = max(0.0, investigation["avg_confidence"] + review.get("confidence_adjustment", 0.0))

    triage_result = {
        "status": "complete",
        "classification": classification,
        "investigation": investigation,
        "review": review,
        "final_confidence": final_confidence,
    }

    yield sse_event("status", {"stage": "blast_radius", "message": "Estimating blast radius..."})
    blast = await estimate_blast_radius(alert, triage_result)

    yield sse_event("status", {"stage": "threat_intel", "message": "Enriching attacker IPs with threat intelligence..."})
    attacker_ips = blast.get("attacker_ips", [])
    threat_intel = await enrich_ips(attacker_ips) if attacker_ips else {}
    if threat_intel:
        yield sse_event("threat_intel", threat_intel)

    yield sse_event("status", {"stage": "correlating", "message": "Checking prior cases..."})
    prior_cases = correlate(alert)

    yield sse_event("status", {"stage": "generating_report", "message": "Generating IR report..."})
    report = generate_ir_report(alert, triage_result)
    report["blast_radius"] = blast
    report["threat_intel"] = threat_intel
    report["prior_cases"] = prior_cases
    report["repeated_attacker"] = len(prior_cases) > 0

    case_id = save_report(report, alert)
    report["case_id"] = case_id

    yield sse_event("complete", report)