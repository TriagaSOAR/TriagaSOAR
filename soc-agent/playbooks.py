# soc-agent/playbooks.py
# YAML-based playbook engine for TriagaSOAR
# Evaluates playbooks after every investigation and executes matching actions.

import os
import re
import json
import glob
import asyncio
import httpx
from datetime import datetime, timezone
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

PLAYBOOKS_DIR = os.getenv("PLAYBOOKS_DIR", "/app/playbooks")


# ── Loading ───────────────────────────────────────────────────────────────────

def load_playbooks() -> list[dict]:
    """Load all enabled playbooks from PLAYBOOKS_DIR."""
    if yaml is None:
        print("[playbooks] PyYAML not installed, playbooks disabled")
        return []

    if not os.path.isdir(PLAYBOOKS_DIR):
        print(f"[playbooks] Directory not found: {PLAYBOOKS_DIR}")
        return []

    playbooks = []
    for path in sorted(glob.glob(os.path.join(PLAYBOOKS_DIR, "*.yml")) +
                       glob.glob(os.path.join(PLAYBOOKS_DIR, "*.yaml"))):
        try:
            with open(path) as f:
                pb = yaml.safe_load(f)
            if not pb.get("enabled", True):
                continue
            if not pb.get("id") or not pb.get("conditions") or not pb.get("actions"):
                print(f"[playbooks] Skipping {path}: missing id, conditions, or actions")
                continue
            pb["_path"] = path
            playbooks.append(pb)
        except Exception as e:
            print(f"[playbooks] Failed to load {path}: {e}")

    print(f"[playbooks] Loaded {len(playbooks)} playbook(s)")
    return playbooks


# ── Condition evaluation ──────────────────────────────────────────────────────

def evaluate_conditions(conditions: dict, report: dict) -> bool:
    """Return True if all conditions match the report. All conditions are ANDed."""
    confidence = report.get("final_confidence", 0) or 0
    severity = (report.get("severity") or "").lower()
    alert_type = (report.get("alert", {}).get("alert_type") or
                  report.get("alert_type") or "").lower()
    techniques = [t.get("technique_id", "") for t in report.get("mitre_techniques", [])]
    tactics = [t.get("tactic", "").lower() for t in report.get("mitre_techniques", [])]

    for key, value in conditions.items():
        if key == "confidence_gte":
            if confidence < float(value):
                return False

        elif key == "confidence_lte":
            if confidence > float(value):
                return False

        elif key == "severity_in":
            if severity not in [s.lower() for s in value]:
                return False

        elif key == "severity":
            if severity != value.lower():
                return False

        elif key == "alert_type":
            if alert_type != value.lower():
                return False

        elif key == "alert_type_in":
            if alert_type not in [a.lower() for a in value]:
                return False

        elif key == "techniques_include":
            # At least one of the listed techniques must be present
            if not any(t in techniques for t in value):
                return False

        elif key == "techniques_include_all":
            # All listed techniques must be present
            if not all(t in techniques for t in value):
                return False

        elif key == "tactics_include":
            if not any(t.lower() in tactics for t in value):
                return False

        elif key == "repeated_attacker":
            if bool(report.get("repeated_attacker")) != bool(value):
                return False

    return True


# ── Template rendering ────────────────────────────────────────────────────────

def render_template(text: str, ctx: dict) -> str:
    """Replace {{variable}} placeholders with context values."""
    if not isinstance(text, str):
        return text

    def replace(match):
        key = match.group(1).strip()
        val = ctx.get(key, match.group(0))
        return str(val) if val is not None else match.group(0)

    return re.sub(r"\{\{(\w+)\}\}", replace, text)


def build_context(report: dict) -> dict:
    """Build template variable context from a report."""
    blast = report.get("blast_radius", {})
    alert = report.get("alert", {})
    affected_users = blast.get("compromised_users", [])
    attacker_ips = blast.get("attacker_ips", [])
    techniques = report.get("mitre_techniques", [])

    return {
        "report_id": report.get("report_id", ""),
        "alert_title": alert.get("title", ""),
        "severity": report.get("severity", ""),
        "confidence": str(round((report.get("final_confidence", 0) or 0) * 100)),
        "alert_type": alert.get("alert_type", ""),
        "affected_user": affected_users[0] if affected_users else "",
        "affected_users": ", ".join(affected_users),
        "attacker_ip": attacker_ips[0] if attacker_ips else "",
        "attacker_ips": ", ".join(attacker_ips),
        "technique_ids": ", ".join(t.get("technique_id", "") for t in techniques),
        "kill_chain": report.get("kill_chain_summary", ""),
        "summary": report.get("summary", ""),
        "index": alert.get("index", "main"),
        "generated_spl": "",  # populated per-action if needed
        # Env vars available for webhook URLs etc.
        "TEAMS_WEBHOOK_URL": os.getenv("TEAMS_WEBHOOK_URL", ""),
        "SLACK_WEBHOOK_URL": os.getenv("SLACK_WEBHOOK_URL", ""),
        "NOTIFICATION_WEBHOOK_URL": os.getenv("NOTIFICATION_WEBHOOK_URL", ""),
    }


# ── Action execution ──────────────────────────────────────────────────────────

async def execute_action(action: dict, ctx: dict, report: dict) -> dict:
    """Execute a single playbook action. Returns result dict."""
    action_type = action.get("type", "")
    result = {"type": action_type, "status": "ok", "detail": ""}

    # Render all string values in the action through the template engine
    rendered = {k: render_template(v, ctx) if isinstance(v, str) else v
                for k, v in action.items()}

    try:
        if action_type == "entra_revoke_sessions":
            from entra import entra_available, revoke_sessions
            if not entra_available():
                result.update({"status": "skipped", "detail": "Entra not configured"})
                return result
            target = rendered.get("target", "")
            if not target:
                result.update({"status": "skipped", "detail": "No target user"})
                return result
            await revoke_sessions(target)
            result["detail"] = f"Revoked sessions for {target}"

        elif action_type == "entra_disable_user":
            from entra import entra_available, disable_user
            if not entra_available():
                result.update({"status": "skipped", "detail": "Entra not configured"})
                return result
            target = rendered.get("target", "")
            if not target:
                result.update({"status": "skipped", "detail": "No target user"})
                return result
            await disable_user(target)
            result["detail"] = f"Disabled {target}"

        elif action_type == "okta_suspend":
            from okta import okta_available, suspend_user
            if not okta_available():
                result.update({"status": "skipped", "detail": "Okta not configured"})
                return result
            target = rendered.get("target", "")
            if not target:
                result.update({"status": "skipped", "detail": "No target user"})
                return result
            await suspend_user(target)
            result["detail"] = f"Suspended {target}"

        elif action_type == "okta_clear_sessions":
            from okta import okta_available, clear_user_sessions
            if not okta_available():
                result.update({"status": "skipped", "detail": "Okta not configured"})
                return result
            target = rendered.get("target", "")
            if not target:
                result.update({"status": "skipped", "detail": "No target user"})
                return result
            await clear_user_sessions(target)
            result["detail"] = f"Cleared sessions for {target}"

        elif action_type == "auth0_block":
            from auth0 import auth0_available, block_user
            if not auth0_available():
                result.update({"status": "skipped", "detail": "Auth0 not configured"})
                return result
            target = rendered.get("target", "")
            if not target:
                result.update({"status": "skipped", "detail": "No target user"})
                return result
            await block_user(target)
            result["detail"] = f"Blocked {target}"

        elif action_type == "splunk_saved_search":
            import httpx as _httpx
            splunk_host = os.getenv("SPLUNK_HOST", "localhost")
            splunk_port = os.getenv("SPLUNK_PORT", "8089")
            splunk_token = os.getenv("SPLUNK_WRITE_TOKEN") or os.getenv("SPLUNK_TOKEN", "")
            name = rendered.get("name", f"Playbook: {ctx.get('alert_title', '')}")
            spl = rendered.get("spl", "")
            if not spl:
                result.update({"status": "skipped", "detail": "No SPL provided"})
                return result
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            async with _httpx.AsyncClient(verify=False, timeout=15.0) as client:
                resp = await client.post(
                    f"https://{splunk_host}:{splunk_port}/servicesNS/nobody/search/saved/searches",
                    headers={"Authorization": f"Bearer {splunk_token}"},
                    data={"name": f"{name} [{ts}]", "search": spl},
                )
            result["detail"] = f"Created saved search '{name}' (HTTP {resp.status_code})"
            if resp.status_code not in (200, 201):
                result["status"] = "error"

        elif action_type == "webhook":
            url = rendered.get("url", "")
            if not url:
                result.update({"status": "skipped", "detail": "No webhook URL"})
                return result
            message = rendered.get("message", f"TriagaSOAR: {ctx.get('alert_title', '')}")
            payload = rendered.get("payload") or {"text": message}
            if isinstance(payload, str):
                payload = json.loads(payload)
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
            result["detail"] = f"Webhook POST {url} → HTTP {resp.status_code}"
            if resp.status_code >= 400:
                result["status"] = "error"

        elif action_type == "teams":
            url = rendered.get("url") or os.getenv("TEAMS_WEBHOOK_URL", "")
            if not url:
                result.update({"status": "skipped", "detail": "No Teams webhook URL"})
                return result
            title = rendered.get("title", f"TriagaSOAR Alert: {ctx.get('alert_title', '')}")
            message = rendered.get("message", ctx.get("summary", ""))
            card = {
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title},
                            {"type": "TextBlock", "text": f"Severity: **{ctx.get('severity', '').upper()}** | Confidence: **{ctx.get('confidence', '0')}%**", "wrap": True},
                            {"type": "TextBlock", "text": message, "wrap": True},
                            {"type": "TextBlock", "text": f"Techniques: {ctx.get('technique_ids', 'none')}", "wrap": True, "isSubtle": True},
                            {"type": "TextBlock", "text": f"Report ID: {ctx.get('report_id', '')}", "wrap": True, "isSubtle": True},
                        ]
                    }
                }]
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=card)
            result["detail"] = f"Teams notification sent → HTTP {resp.status_code}"
            if resp.status_code >= 400:
                result["status"] = "error"

        else:
            result.update({"status": "skipped", "detail": f"Unknown action type: {action_type}"})

    except Exception as e:
        result.update({"status": "error", "detail": str(e)})

    return result


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_playbooks(report: dict, db_conn=None) -> list[dict]:
    """
    Evaluate all enabled playbooks against a completed investigation report.
    Execute matching playbooks and return execution records.
    """
    playbooks = load_playbooks()
    if not playbooks:
        return []

    ctx = build_context(report)
    executions = []

    for pb in playbooks:
        pb_id = pb.get("id", "unknown")
        pb_name = pb.get("name", pb_id)
        conditions = pb.get("conditions", {})

        if not evaluate_conditions(conditions, report):
            continue

        print(f"[playbooks] Playbook '{pb_name}' matched — executing {len(pb['actions'])} action(s)")

        action_results = []
        for action in pb.get("actions", []):
            action_result = await execute_action(action, ctx, report)
            action_results.append(action_result)
            print(f"[playbooks]   {action['type']} → {action_result['status']}: {action_result['detail']}")

        execution = {
            "playbook_id": pb_id,
            "playbook_name": pb_name,
            "report_id": report.get("report_id", ""),
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "conditions_matched": conditions,
            "action_results": action_results,
            "overall_status": "ok" if all(r["status"] in ("ok", "skipped") for r in action_results) else "partial",
        }
        executions.append(execution)

        # Persist to DB if connection provided
        if db_conn is not None:
            try:
                db_conn.execute(
                    """INSERT INTO playbook_executions
                       (playbook_id, playbook_name, report_id, triggered_at, action_results, overall_status)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (pb_id, pb_name, report.get("report_id", ""),
                     execution["triggered_at"],
                     json.dumps(action_results),
                     execution["overall_status"])
                )
                db_conn.commit()
            except Exception as e:
                print(f"[playbooks] Failed to persist execution: {e}")

    return executions