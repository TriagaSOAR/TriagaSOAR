import json
from datetime import datetime, timezone
from mitre import map_findings_to_mitre, assemble_kill_chain


def generate_ir_report(alert: dict, triage_result: dict) -> dict:
    """Generate a structured IR report from triage output."""
    investigation = triage_result.get("investigation", {})
    review = triage_result.get("review", {})
    classification = triage_result.get("classification", {})

    # Collect raw event text from extra findings for MITRE mapping
    raw_events = []
    for ef in investigation.get("extra_findings", []):
        for s in ef.get("sample", []):
            raw_events.append(s.get("_raw", ""))

    # Also feed queries_run and finding text as signal for MITRE matching
    extra_signals = investigation.get("queries_run", [])
    extra_signals += [f.get("finding", "") for f in investigation.get("findings", [])]

    # Map to MITRE
    techniques = map_findings_to_mitre(
        investigation.get("findings", []),
        raw_events + extra_signals,
    )
    kill_chain = assemble_kill_chain(techniques)

    # Evidence gate – floor confidence only if no high-confidence findings
    # and no extra findings returned results
    evidence_found = (
        any(f.get("confidence", 0) >= 0.7 for f in investigation.get("findings", []))
        or any(ef.get("result_count", 0) > 0 for ef in investigation.get("extra_findings", []))
    )
    final_confidence = triage_result.get("final_confidence", 0)
    if not evidence_found:
        final_confidence = min(final_confidence, 0.2)

    return {
        "report_id": f"IR-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "title": alert.get("title"),
            "index": alert.get("index", "main"),
            "time_range": f"{alert.get('earliest', '-1h')} to {alert.get('latest', 'now')}",
        },
        "severity": classification.get("severity"),
        "alert_type": classification.get("alert_type"),
        "final_confidence": round(final_confidence, 2),
        "summary": classification.get("reason"),
        "findings": investigation.get("findings", []),
        "queries_run": [q for q in investigation.get("queries_run", []) if q.strip().startswith("index=")],
        "adversarial_review": {
            "verdict": review.get("verdict"),
            "critique": review.get("critique"),
        },
        "mitre_techniques": kill_chain,
        "kill_chain_summary": " → ".join(
            f"{t['technique_id']} ({t['tactic']})" for t in kill_chain
        ),
        "recommendations": _generate_recommendations(kill_chain, classification),
    }


def _generate_recommendations(kill_chain: list, classification: dict) -> list[str]:
    recs = []
    all_ids = set()
    for t in kill_chain:
        all_ids.add(t["technique_id"])
        all_ids.add(t["parent_id"])

    if "T1110" in all_ids:
        recs.append("Enable account lockout after 5 failed attempts")
        recs.append("Implement MFA for SSH access")
        recs.append("Restrict SSH access to known IP ranges")

    if "T1078" in all_ids:
        recs.append("Audit all active sessions from suspicious source IPs")
        recs.append("Force password reset for compromised accounts")

    if "T1548" in all_ids:
        recs.append("Review sudoers file for unnecessary privileges")
        recs.append("Enable sudo command logging and alerting")
        recs.append("Consider removing /bin/bash from allowed sudo commands")

    if "T1021" in all_ids:
        recs.append("Block source IP at firewall level")
        recs.append("Review SSH key-based authentication policy")

    return recs