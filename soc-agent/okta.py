import os
import httpx
from datetime import datetime, timezone, timedelta

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "")

OKTA_BASE = f"https://{OKTA_DOMAIN}/api/v1"


def okta_available() -> bool:
    return bool(OKTA_DOMAIN and OKTA_API_TOKEN)


def _headers() -> dict:
    return {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def okta_get(path: str, params: dict = None) -> list | dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{OKTA_BASE}{path}",
            headers=_headers(),
            params=params or {},
        )
        resp.raise_for_status()
        return resp.json()


async def okta_post(path: str, body: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{OKTA_BASE}{path}",
            headers=_headers(),
            json=body or {},
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


async def okta_put(path: str, body: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.put(
            f"{OKTA_BASE}{path}",
            headers=_headers(),
            json=body or {},
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}


# ── Users ─────────────────────────────────────────────────────────────────────

async def get_users(limit: int = 50, search: str = None) -> list:
    params = {"limit": limit}
    if search:
        params["search"] = search
    return await okta_get("/users", params=params)


async def get_user(user_id_or_login: str) -> dict:
    return await okta_get(f"/users/{user_id_or_login}")


async def get_user_groups(user_id: str) -> list:
    return await okta_get(f"/users/{user_id}/groups")


async def suspend_user(user_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{OKTA_BASE}/users/{user_id}/lifecycle/suspend",
            headers=_headers(),
        )
        resp.raise_for_status()
    return {"action": "suspend_user", "user_id": user_id, "status": "success"}


async def unsuspend_user(user_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{OKTA_BASE}/users/{user_id}/lifecycle/unsuspend",
            headers=_headers(),
        )
        resp.raise_for_status()
    return {"action": "unsuspend_user", "user_id": user_id, "status": "success"}


async def deactivate_user(user_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{OKTA_BASE}/users/{user_id}/lifecycle/deactivate",
            headers=_headers(),
        )
        resp.raise_for_status()
    return {"action": "deactivate_user", "user_id": user_id, "status": "success"}


async def clear_user_sessions(user_id: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.delete(
            f"{OKTA_BASE}/users/{user_id}/sessions",
            headers=_headers(),
        )
        resp.raise_for_status()
    return {"action": "clear_sessions", "user_id": user_id, "status": "success"}


# ── System logs ───────────────────────────────────────────────────────────────

async def get_logs(hours: int = 24, limit: int = 100, filter_str: str = None) -> list:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    params = {"since": since, "limit": limit, "sortOrder": "DESCENDING"}
    if filter_str:
        params["filter"] = filter_str
    return await okta_get("/logs", params=params)


async def get_failed_logins(hours: int = 24, limit: int = 50) -> list:
    return await get_logs(
        hours=hours,
        limit=limit,
        filter_str='eventType eq "user.session.start" and outcome.result eq "FAILURE"',
    )


async def get_suspicious_activity(hours: int = 48, limit: int = 50) -> list:
    return await get_logs(
        hours=hours,
        limit=limit,
        filter_str='eventType sw "security."',
    )


# ── Threat insights ───────────────────────────────────────────────────────────

async def get_threat_insights() -> dict:
    try:
        return await okta_get("/threats/configuration")
    except Exception:
        return {}


# ── Enrichment ────────────────────────────────────────────────────────────────

async def enrich_user_from_okta(login_or_id: str) -> dict:
    if not okta_available():
        return {"available": False, "message": "Okta not configured"}

    try:
        user = await get_user(login_or_id)
        user_id = user.get("id")
        profile = user.get("profile", {})

        logs = await get_logs(hours=48, limit=50,
            filter_str=f'actor.alternateId eq "{profile.get("login", login_or_id)}"'
        )
        failed = [l for l in logs if l.get("outcome", {}).get("result") == "FAILURE"]
        recent_ips = list({
            l.get("client", {}).get("ipAddress")
            for l in logs
            if l.get("client", {}).get("ipAddress")
        })
        recent_apps = list({
            l.get("target", [{}])[0].get("displayName")
            for l in logs
            if l.get("target")
        })

        return {
            "available": True,
            "id": user_id,
            "login": profile.get("login"),
            "display_name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            "email": profile.get("email"),
            "status": user.get("status"),
            "created": user.get("created"),
            "last_login": user.get("lastLogin"),
            "last_updated": user.get("lastUpdated"),
            "password_changed": user.get("passwordChanged"),
            "dept": profile.get("department"),
            "title": profile.get("title"),
            "signin_count_48h": len(logs),
            "failed_signin_count_48h": len(failed),
            "recent_ips": recent_ips[:10],
            "recent_apps": [a for a in recent_apps if a][:10],
        }
    except Exception as e:
        return {"available": False, "message": str(e)}