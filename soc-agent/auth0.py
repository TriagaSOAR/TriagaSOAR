import os
import httpx
from datetime import datetime, timezone, timedelta

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "")

_token_cache: dict = {"token": None, "expires_at": 0}


def auth0_available() -> bool:
    return bool(AUTH0_DOMAIN and AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET)


async def get_token() -> str:
    now = datetime.now(timezone.utc).timestamp()
    if _token_cache["token"] and _token_cache["expires_at"] > now + 60:
        return _token_cache["token"]

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        _token_cache["token"] = data["access_token"]
        _token_cache["expires_at"] = now + data.get("expires_in", 86400)
        return _token_cache["token"]


async def auth0_get(path: str, params: dict = None) -> list | dict:
    token = await get_token()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"https://{AUTH0_DOMAIN}/api/v2{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        resp.raise_for_status()
        return resp.json()


async def auth0_patch(path: str, body: dict) -> dict:
    token = await get_token()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.patch(
            f"https://{AUTH0_DOMAIN}/api/v2{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
        resp.raise_for_status()
        return resp.json()


# ── Users ─────────────────────────────────────────────────────────────────────

async def get_users(page: int = 0, per_page: int = 50, q: str = None) -> list:
    params = {"page": page, "per_page": per_page, "include_totals": "false"}
    if q:
        params["q"] = q
        params["search_engine"] = "v3"
    return await auth0_get("/users", params=params)


async def get_user(user_id: str) -> dict:
    return await auth0_get(f"/users/{user_id}")


async def block_user(user_id: str) -> dict:
    await auth0_patch(f"/users/{user_id}", {"blocked": True})
    return {"action": "block_user", "user_id": user_id, "status": "success"}


async def unblock_user(user_id: str) -> dict:
    await auth0_patch(f"/users/{user_id}", {"blocked": False})
    return {"action": "unblock_user", "user_id": user_id, "status": "success"}


# ── Logs ──────────────────────────────────────────────────────────────────────

async def get_logs(per_page: int = 100, q: str = None) -> list:
    params = {"per_page": per_page, "sort": "date:-1", "include_totals": "false"}
    if q:
        params["q"] = q
    return await auth0_get("/logs", params=params)


async def get_failed_logins(per_page: int = 50) -> list:
    return await get_logs(per_page=per_page, q='type:"f"')


async def get_suspicious_logins(per_page: int = 50) -> list:
    # Auth0 log types: fp=brute force, limit_wc=anomaly, cls=credential stuffing
    return await get_logs(per_page=per_page, q='type:"fp" OR type:"limit_wc" OR type:"cls"')


# ── Attack protection ─────────────────────────────────────────────────────────

async def get_brute_force_config() -> dict:
    try:
        return await auth0_get("/attack-protection/brute-force-protection")
    except Exception:
        return {}


async def get_suspicious_ip_config() -> dict:
    try:
        return await auth0_get("/attack-protection/suspicious-ip-throttling")
    except Exception:
        return {}


async def get_breached_password_config() -> dict:
    try:
        return await auth0_get("/attack-protection/breached-password-detection")
    except Exception:
        return {}


# ── Enrichment ────────────────────────────────────────────────────────────────

async def enrich_user_from_auth0(user_id_or_email: str) -> dict:
    if not auth0_available():
        return {"available": False, "message": "Auth0 not configured"}

    try:
        # Try direct lookup first, fall back to search
        try:
            user = await get_user(user_id_or_email)
        except Exception:
            users = await get_users(q=f'email:"{user_id_or_email}"')
            if not users:
                return {"available": False, "message": f"User {user_id_or_email} not found"}
            user = users[0]

        user_id = user.get("user_id")
        logs = await get_logs(per_page=50, q=f'user_id:"{user_id}"')
        failed = [l for l in logs if l.get("type") in ("f", "fp", "fu", "fco")]
        recent_ips = list({l.get("ip") for l in logs if l.get("ip")})
        recent_apps = list({l.get("client_name") for l in logs if l.get("client_name")})

        return {
            "available": True,
            "user_id": user_id,
            "email": user.get("email"),
            "name": user.get("name"),
            "nickname": user.get("nickname"),
            "picture": user.get("picture"),
            "blocked": user.get("blocked", False),
            "email_verified": user.get("email_verified"),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
            "last_ip": user.get("last_ip"),
            "logins_count": user.get("logins_count", 0),
            "identities": [i.get("provider") for i in user.get("identities", [])],
            "signin_count_48h": len(logs),
            "failed_signin_count_48h": len(failed),
            "recent_ips": list(recent_ips)[:10],
            "recent_apps": [a for a in recent_apps if a][:10],
        }
    except Exception as e:
        return {"available": False, "message": str(e)}