import os
import httpx
from datetime import datetime, timezone, timedelta
from functools import lru_cache

TENANT_ID = os.getenv("ENTRA_TENANT_ID", "")
CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

_token_cache: dict = {"token": None, "expires_at": 0}


def entra_available() -> bool:
    return bool(TENANT_ID and CLIENT_ID and CLIENT_SECRET)


async def get_token() -> str:
    now = datetime.now(timezone.utc).timestamp()
    if _token_cache["token"] and _token_cache["expires_at"] > now + 60:
        return _token_cache["token"]

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
        })
        resp.raise_for_status()
        data = resp.json()
        _token_cache["token"] = data["access_token"]
        _token_cache["expires_at"] = now + data.get("expires_in", 3600)
        return _token_cache["token"]


async def graph_get(path: str, beta: bool = False, params: dict = None) -> dict:
    token = await get_token()
    base = GRAPH_BETA if beta else GRAPH_BASE
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{base}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        resp.raise_for_status()
        return resp.json()


async def graph_post(path: str, body: dict, beta: bool = False) -> dict:
    token = await get_token()
    base = GRAPH_BETA if beta else GRAPH_BASE
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


async def graph_patch(path: str, body: dict) -> None:
    token = await get_token()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.patch(
            f"{GRAPH_BASE}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
        resp.raise_for_status()


# ── Sign-in logs ──────────────────────────────────────────────────────────────

async def get_signin_logs(hours: int = 24, top: int = 50, user_upn: str = None, ip: str = None) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filters = [f"createdDateTime ge {since}"]
    if user_upn:
        filters.append(f"userPrincipalName eq '{user_upn}'")
    if ip:
        filters.append(f"ipAddress eq '{ip}'")

    data = await graph_get("/auditLogs/signIns", params={
        "$filter": " and ".join(filters),
        "$top": top,
        "$orderby": "createdDateTime desc",
    })
    return data.get("value", [])


async def get_failed_signins(hours: int = 24, top: int = 50) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = await graph_get("/auditLogs/signIns", params={
        "$filter": f"createdDateTime ge {since} and status/errorCode ne 0",
        "$top": top,
        "$orderby": "createdDateTime desc",
    })
    return data.get("value", [])


# ── Risky users + detections ──────────────────────────────────────────────────

async def get_risky_users(risk_level: str = None) -> list:
    params = {"$top": 100}
    if risk_level:
        params["$filter"] = f"riskLevel eq '{risk_level}'"
    data = await graph_get("/identityProtection/riskyUsers", params=params)
    return data.get("value", [])


async def get_risk_detections(hours: int = 48, top: int = 50) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = await graph_get("/identityProtection/riskDetections", params={
        "$filter": f"detectedDateTime ge {since}",
        "$top": top,
        "$orderby": "detectedDateTime desc",
    })
    return data.get("value", [])


async def get_risky_user_history(user_id: str) -> list:
    data = await graph_get(f"/identityProtection/riskyUsers/{user_id}/history")
    return data.get("value", [])


# ── Security alerts ───────────────────────────────────────────────────────────

async def get_security_alerts(hours: int = 48, top: int = 50, severity: str = None) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filters = [f"createdDateTime ge {since}"]
    if severity:
        filters.append(f"severity eq '{severity}'")
    data = await graph_get("/security/alerts_v2", params={
        "$filter": " and ".join(filters),
        "$top": top,
        "$orderby": "createdDateTime desc",
    })
    return data.get("value", [])


# ── Audit logs ────────────────────────────────────────────────────────────────

async def get_audit_logs(hours: int = 24, top: int = 50, category: str = None) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    filters = [f"activityDateTime ge {since}"]
    if category:
        filters.append(f"category eq '{category}'")
    data = await graph_get("/auditLogs/directoryAudits", params={
        "$filter": " and ".join(filters),
        "$top": top,
        "$orderby": "activityDateTime desc",
    })
    return data.get("value", [])


# ── User lookups ──────────────────────────────────────────────────────────────

async def get_user(upn_or_id: str) -> dict:
    data = await graph_get(f"/users/{upn_or_id}", params={
        "$select": "id,displayName,userPrincipalName,accountEnabled,lastPasswordChangeDateTime,createdDateTime,assignedLicenses,jobTitle,department,officeLocation"
    })
    return data


async def get_user_by_ip(ip: str, hours: int = 24) -> list[dict]:
    logs = await get_signin_logs(hours=hours, ip=ip, top=20)
    seen = {}
    for log in logs:
        upn = log.get("userPrincipalName")
        if upn and upn not in seen:
            seen[upn] = {
                "userPrincipalName": upn,
                "displayName": log.get("userDisplayName"),
                "userId": log.get("userId"),
                "lastSeen": log.get("createdDateTime"),
                "appDisplayName": log.get("appDisplayName"),
                "location": log.get("location", {}),
                "riskLevelDuringSignIn": log.get("riskLevelDuringSignIn"),
            }
    return list(seen.values())


# ── Response actions ──────────────────────────────────────────────────────────

async def disable_user(user_id: str) -> dict:
    await graph_patch(f"/users/{user_id}", {"accountEnabled": False})
    return {"action": "disable_user", "user_id": user_id, "status": "success"}


async def revoke_sessions(user_id: str) -> dict:
    await graph_post(f"/users/{user_id}/revokeSignInSessions", {})
    return {"action": "revoke_sessions", "user_id": user_id, "status": "success"}


async def enable_user(user_id: str) -> dict:
    await graph_patch(f"/users/{user_id}", {"accountEnabled": True})
    return {"action": "enable_user", "user_id": user_id, "status": "success"}


# ── Enrichment helper (called from agent during investigation) ────────────────

async def enrich_user_from_entra(upn: str) -> dict:
    """
    Called by the agent to enrich a username found in Splunk logs.
    Returns a compact dict with risk posture and recent activity.
    """
    if not entra_available():
        return {"available": False, "message": "Entra ID not configured"}

    try:
        user = await get_user(upn)
        user_id = user.get("id")

        signin_logs = await get_signin_logs(hours=48, top=20, user_upn=upn)
        failed = [s for s in signin_logs if s.get("status", {}).get("errorCode", 0) != 0]

        risky_users = await get_risky_users()
        risky_match = next((r for r in risky_users if r.get("userPrincipalName") == upn), None)

        recent_ips = list({s.get("ipAddress") for s in signin_logs if s.get("ipAddress")})
        recent_apps = list({s.get("appDisplayName") for s in signin_logs if s.get("appDisplayName")})
        locations = list({
            f"{s['location']['city']}, {s['location']['countryOrRegion']}"
            for s in signin_logs
            if s.get("location", {}).get("city")
        })

        return {
            "available": True,
            "upn": upn,
            "display_name": user.get("displayName"),
            "account_enabled": user.get("accountEnabled"),
            "job_title": user.get("jobTitle"),
            "department": user.get("department"),
            "risk_level": risky_match.get("riskLevel") if risky_match else "none",
            "risk_state": risky_match.get("riskState") if risky_match else "none",
            "risky_user_id": risky_match.get("id") if risky_match else None,
            "signin_count_48h": len(signin_logs),
            "failed_signin_count_48h": len(failed),
            "recent_ips": recent_ips[:10],
            "recent_apps": recent_apps[:10],
            "sign_in_locations": locations[:10],
            "last_password_change": user.get("lastPasswordChangeDateTime"),
        }
    except Exception as e:
        return {"available": False, "message": str(e)}


async def enrich_users_from_entra(upns: list[str]) -> dict:
    import asyncio
    results = await asyncio.gather(*[enrich_user_from_entra(u) for u in upns], return_exceptions=True)
    return {
        upn: (r if not isinstance(r, Exception) else {"available": False, "message": str(r)})
        for upn, r in zip(upns, results)
    }