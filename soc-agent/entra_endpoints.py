# ── Entra ID endpoints ────────────────────────────────────────────────────────
# Add to imports at top of main.py:
# from entra import (
#     entra_available, get_signin_logs, get_failed_signins, get_risky_users,
#     get_risk_detections, get_security_alerts, get_audit_logs, get_user,
#     get_user_by_ip, disable_user, revoke_sessions, enable_user,
#     enrich_user_from_entra, enrich_users_from_entra,
# )


@app.get("/entra/health")
async def entra_health():
    if not entra_available():
        return {"available": False, "message": "ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET not set"}
    try:
        from entra import get_token
        await get_token()
        return {"available": True, "tenant_id": os.getenv("ENTRA_TENANT_ID")}
    except Exception as e:
        return {"available": False, "message": str(e)}


@app.get("/entra/signins")
async def entra_signins(hours: int = 24, top: int = 50, user: str = None, ip: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_signin_logs
    return {"signins": await get_signin_logs(hours=hours, top=top, user_upn=user, ip=ip)}


@app.get("/entra/signins/failed")
async def entra_failed_signins(hours: int = 24, top: int = 50):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_failed_signins
    logs = await get_failed_signins(hours=hours, top=top)
    return {"count": len(logs), "signins": logs}


@app.get("/entra/risky-users")
async def entra_risky_users(risk_level: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_risky_users
    users = await get_risky_users(risk_level=risk_level)
    return {"count": len(users), "users": users}


@app.get("/entra/risk-detections")
async def entra_risk_detections(hours: int = 48, top: int = 50):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_risk_detections
    detections = await get_risk_detections(hours=hours, top=top)
    return {"count": len(detections), "detections": detections}


@app.get("/entra/alerts")
async def entra_security_alerts(hours: int = 48, top: int = 50, severity: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_security_alerts
    alerts = await get_security_alerts(hours=hours, top=top, severity=severity)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/entra/audit-logs")
async def entra_audit_logs(hours: int = 24, top: int = 50, category: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_audit_logs
    logs = await get_audit_logs(hours=hours, top=top, category=category)
    return {"count": len(logs), "logs": logs}


@app.get("/entra/users/{upn_or_id}")
async def entra_user(upn_or_id: str):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import enrich_user_from_entra
    return await enrich_user_from_entra(upn_or_id)


@app.get("/entra/users/by-ip/{ip}")
async def entra_users_by_ip(ip: str, hours: int = 24):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    from entra import get_user_by_ip
    users = await get_user_by_ip(ip=ip, hours=hours)
    return {"ip": ip, "users": users}


@app.post("/entra/actions/disable-user")
async def entra_disable_user(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    from entra import disable_user
    result = await disable_user(user_id)
    # Log action to SQLite
    conn = get_connection()
    conn.execute(
        "INSERT INTO response_actions (action, target, performed_at, details) VALUES (?,?,?,?)",
        ("disable_user", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result))
    )
    conn.commit()
    conn.close()
    return result


@app.post("/entra/actions/revoke-sessions")
async def entra_revoke_sessions(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    from entra import revoke_sessions
    result = await revoke_sessions(user_id)
    conn = get_connection()
    conn.execute(
        "INSERT INTO response_actions (action, target, performed_at, details) VALUES (?,?,?,?)",
        ("revoke_sessions", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result))
    )
    conn.commit()
    conn.close()
    return result


@app.post("/entra/actions/enable-user")
async def entra_enable_user(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    from entra import enable_user
    result = await enable_user(user_id)
    conn = get_connection()
    conn.execute(
        "INSERT INTO response_actions (action, target, performed_at, details) VALUES (?,?,?,?)",
        ("enable_user", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result))
    )
    conn.commit()
    conn.close()
    return result


@app.get("/entra/actions")
async def entra_action_log():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM response_actions ORDER BY performed_at DESC LIMIT 100"
        ).fetchall()
        return {"actions": [dict(r) for r in rows]}
    finally:
        conn.close()