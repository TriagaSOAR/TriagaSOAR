import re
from splunk_mcp import run_query


async def estimate_blast_radius(alert: dict, report: dict) -> dict:
    """
    Estimate blast radius by finding what else has interacted
    with the attacker IP and compromised user in Splunk.
    """
    index = alert.get("index", "main")
    earliest = alert.get("earliest", "-24h")

    # Extract IPs and users from report findings
    ips = set()
    users = set()

    search_terms = alert.get("search_terms", "")
    ips.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", search_terms))

    for finding in report.get("findings", []):
        text = finding.get("finding", "")
        ips.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        found_users = re.findall(r"(?:user|for)\s+'?([a-zA-Z0-9_-]+)'?", text)
        for u in found_users:
            if u not in ("root", "the", "a", "an", "attempts", "invalid", "admin"):
                users.add(u)

    results = {
        "attacker_ips": list(ips),
        "compromised_users": list(users),
        "affected_hosts": [],
        "related_events": [],
        "risk_summary": "",
    }

    if not ips and not users:
        results["risk_summary"] = "No entities extracted — blast radius unknown"
        return results

    # Find all hosts that saw traffic from attacker IPs
    affected_hosts = set()
    related_events = []

    for ip in ips:
        rows = await run_query(
            f'index={index} "{ip}" | stats count by host | sort -count',
            earliest=earliest,
        )
        for row in rows:
            host = row.get("host")
            if host:
                affected_hosts.add(host)
                related_events.append({
                    "entity": ip,
                    "type": "ip",
                    "host": host,
                    "event_count": row.get("count", 0),
                })

    # Find all activity by compromised users
    for user in users:
        rows = await run_query(
            f'index={index} "{user}" "sudo" | stats count by host | sort -count',
            earliest=earliest,
        )
        for row in rows:
            host = row.get("host")
            if host:
                affected_hosts.add(host)
                related_events.append({
                    "entity": user,
                    "type": "user",
                    "host": host,
                    "event_count": row.get("count", 0),
                })

    results["affected_hosts"] = list(affected_hosts)
    results["related_events"] = related_events

    # Risk summary
    host_count = len(affected_hosts)
    ip_count = len(ips)
    user_count = len(users)

    if host_count == 0:
        results["risk_summary"] = "No lateral spread detected"
    elif host_count == 1:
        results["risk_summary"] = f"Activity contained to 1 host — {ip_count} attacker IP(s), {user_count} compromised user(s)"
    else:
        results["risk_summary"] = f"SPREAD DETECTED — {host_count} hosts affected by {ip_count} attacker IP(s) and {user_count} compromised user(s)"

    return results