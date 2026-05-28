import httpx
import os
from datetime import datetime, timezone

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


async def lookup_ip(ip: str) -> dict:
    """Look up an IP on AbuseIPDB. Returns graceful degradation if no API key."""
    if not ABUSEIPDB_API_KEY:
        return {
            "available": False,
            "message": "No AbuseIPDB API key configured. Add ABUSEIPDB_API_KEY to your .env and restart.",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            return {
                "available": True,
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", ""),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt", None),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "usage_type": data.get("usageType", "Unknown"),
                "threat_level": _score_to_threat_level(data.get("abuseConfidenceScore", 0)),
            }
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 402:
            return {"available": False, "message": "AbuseIPDB API limit reached for today."}
        if e.response.status_code == 422:
            return {"available": False, "message": f"Invalid IP address: {ip}"}
        return {"available": False, "message": f"AbuseIPDB API error: {e.response.status_code}"}
    except Exception as e:
        return {"available": False, "message": f"Threat intel lookup failed: {str(e)}"}


async def enrich_ips(ips: list[str]) -> dict[str, dict]:
    """Enrich multiple IPs, deduplicating and caching results."""
    results = {}
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        # Skip private/loopback IPs
        if _is_private(ip):
            results[ip] = {"available": False, "message": "Private IP — no threat intel available"}
            continue
        results[ip] = await lookup_ip(ip)
    return results


def _score_to_threat_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
        )
    except ValueError:
        return False