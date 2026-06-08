// auth/src/routes/login.rs
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::{AppState, crypto, db};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub requires_totp: bool,
    pub requires_totp_enrollment: bool,
    pub auth_level: i32,
    pub username: String,
    pub role: String,
}

pub async fn login(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let accept_lang = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let accept_enc = headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let fingerprint = crypto::device_fingerprint(&ua, &accept_lang, &accept_enc);

    // Find user
    let user = match db::users::find_by_username(&state.db, &body.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Log failed attempt
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "auth.login.failure".into(),
                actor_id: None,
                actor_username: Some(body.username.clone()),
                actor_ip: Some(ip),
                actor_ua: Some(ua),
                target_type: Some("user".into()),
                target_id: Some(body.username.clone()),
                action: "login".into(),
                outcome: "failure".into(),
                reason: Some("user_not_found".into()),
                metadata: None,
            }).await;
            return auth_failure("Invalid credentials");
        }
        Err(e) => {
            tracing::error!("DB error during login: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Check lockout
    if let Some(lockout) = user.lockout_until {
        if lockout > time::OffsetDateTime::now_utc() {
            return auth_failure("Account temporarily locked");
        }
    }

    // Verify password
    if !crypto::verify_password(&body.password, &user.password_hash) {
        let _ = db::users::increment_failed_attempts(&state.db, &body.username).await;
        let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
            event_type: "auth.login.failure".into(),
            actor_id: Some(user.id),
            actor_username: Some(user.username.clone()),
            actor_ip: Some(ip),
            actor_ua: Some(ua),
            target_type: Some("user".into()),
            target_id: Some(user.id.to_string()),
            action: "login".into(),
            outcome: "failure".into(),
            reason: Some("wrong_password".into()),
            metadata: None,
        }).await;
        return auth_failure("Invalid credentials");
    }

    // TOTP check
    if user.totp_enrolled {
        let code = match &body.totp_code {
            Some(c) => c.clone(),
            None => {
                return Json(LoginResponse {
                    success: false,
                    requires_totp: true,
                    requires_totp_enrollment: false,
                    auth_level: 0,
                    username: user.username,
                    role: user.role,
                }).into_response();
            }
        };

        let secret = user.totp_secret.as_deref().unwrap_or("");
        if !verify_totp(secret, &code) {
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "auth.login.failure".into(),
                actor_id: Some(user.id),
                actor_username: Some(user.username.clone()),
                actor_ip: Some(ip),
                actor_ua: Some(ua.clone()),
                target_type: Some("user".into()),
                target_id: Some(user.id.to_string()),
                action: "login".into(),
                outcome: "failure".into(),
                reason: Some("totp_invalid".into()),
                metadata: None,
            }).await;
            return auth_failure("Invalid TOTP code");
        }
    }

    // Create session
    let token = match db::sessions::create(
        &state.db, user.id, ip, &ua, &fingerprint
    ).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Session creation error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Reset failed attempts
    let _ = db::users::reset_failed_attempts(&state.db, user.id).await;

    // Audit
    let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
        event_type: "auth.login.success".into(),
        actor_id: Some(user.id),
        actor_username: Some(user.username.clone()),
        actor_ip: Some(ip),
        actor_ua: Some(ua),
        target_type: Some("session".into()),
        target_id: None,
        action: "login".into(),
        outcome: "success".into(),
        reason: None,
        metadata: None,
    }).await;

    let requires_enrollment = !user.totp_enrolled;

    // Set httponly secure samesite=strict cookie
    let cookie = format!(
        "soc_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800",
        token
    );

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            success: true,
            requires_totp: false,
            requires_totp_enrollment: requires_enrollment,
            auth_level: 1,
            username: user.username,
            role: user.role,
        }),
    )
        .into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Extract and invalidate session
    if let Some(token) = extract_session_token(&headers) {
        // Find and invalidate
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if let Ok(Some(session)) = db::sessions::validate(&state.db, &token, ip, &ua).await {
            let _ = db::sessions::invalidate(&state.db, session.id, "logout").await;
        }
    }

    let clear_cookie = "soc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({"success": true})),
    )
        .into_response()
}

fn auth_failure(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"success": false, "error": msg})),
    )
        .into_response()
}

fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookies.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("soc_session=") {
            return Some(value.to_string());
        }
    }
    None
}

fn verify_totp(secret: &str, code: &str) -> bool {
    crate::totp::verify(secret, code)
}