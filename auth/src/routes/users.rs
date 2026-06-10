// auth/src/routes/users.rs
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{AppState, crypto, db};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: Option<String>, // defaults to "analyst", admin can set "admin"
}

#[derive(Serialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub active: bool,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

async fn require_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    ip: std::net::IpAddr,
) -> Result<db::users::User, Response> {
    let token = extract_session_token(headers)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let session = db::sessions::validate(&state.db, &token, ip, &ua)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    let user = db::users::find_by_id(&state.db, session.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    if user.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin role required"})),
        ).into_response());
    }

    Ok(user)
}

async fn require_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    ip: std::net::IpAddr,
) -> Result<(db::sessions::Session, db::users::User), Response> {
    let token = extract_session_token(headers)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let session = db::sessions::validate(&state.db, &token, ip, &ua)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    let user = db::users::find_by_id(&state.db, session.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    Ok((session, user))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn list_users(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers, addr.ip()).await {
        return r;
    }

    match db::users::list_all(&state.db).await {
        Ok(users) => {
            let summaries: Vec<UserSummary> = users.into_iter().map(|u| UserSummary {
                id: u.id.to_string(),
                username: u.username,
                email: u.email,
                role: u.role,
                active: u.active,
            }).collect();
            Json(serde_json::json!({"users": summaries})).into_response()
        }
        Err(e) => {
            tracing::error!("list_users error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn create_user(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Response {
    let admin = match require_admin(&state, &headers, addr.ip()).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    // Validate
    if body.username.len() < 3 || body.username.len() > 32 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "username must be 3-32 characters"}))).into_response();
    }
    if body.password.len() < 12 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "password must be at least 12 characters"}))).into_response();
    }

    // Only admin can assign admin role
    let role = match body.role.as_deref() {
        Some("admin") => "admin",
        _ => "analyst",
    };

    let hash = match crypto::hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hash_password error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match db::users::create_user(&state.db, &body.username, &body.email, &hash, role).await {
        Ok(user_id) => {
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "admin.user.create".into(),
                actor_id: Some(admin.id),
                actor_username: Some(admin.username),
                actor_ip: Some(addr.ip()),
                actor_ua: None,
                target_type: Some("user".into()),
                target_id: Some(user_id.to_string()),
                action: "create_user".into(),
                outcome: "success".into(),
                reason: Some(format!("created {} with role {}", body.username, role)),
                metadata: None,
            }).await;
            (StatusCode::CREATED, Json(serde_json::json!({
                "id": user_id.to_string(),
                "username": body.username,
                "role": role,
            }))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("unique") || msg.contains("duplicate") {
                (StatusCode::CONFLICT, Json(serde_json::json!({"error": "username or email already exists"}))).into_response()
            } else {
                tracing::error!("create_user error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

pub async fn deactivate_user(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<Uuid>,
) -> Response {
    let admin = match require_admin(&state, &headers, addr.ip()).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    // Can't deactivate self
    if admin.id == user_id {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "cannot deactivate your own account"}))).into_response();
    }

    match db::users::deactivate_user(&state.db, user_id).await {
        Ok(true) => {
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "admin.user.deactivate".into(),
                actor_id: Some(admin.id),
                actor_username: Some(admin.username),
                actor_ip: Some(addr.ip()),
                actor_ua: None,
                target_type: Some("user".into()),
                target_id: Some(user_id.to_string()),
                action: "deactivate_user".into(),
                outcome: "success".into(),
                reason: None,
                metadata: None,
            }).await;
            Json(serde_json::json!({"success": true})).into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "user not found"}))).into_response(),
        Err(e) => {
            tracing::error!("deactivate_user error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Response {
    let (_, user) = match require_session(&state, &headers, addr.ip()).await {
        Ok(s) => s,
        Err(r) => return r,
    };

    if body.new_password.len() < 12 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "new password must be at least 12 characters"}))).into_response();
    }

    // Verify current password
    if !crypto::verify_password(&body.current_password, &user.password_hash) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "current password incorrect"}))).into_response();
    }

    let new_hash = match crypto::hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hash_password error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match db::users::update_password(&state.db, user.id, &new_hash).await {
        Ok(()) => {
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "auth.password.change".into(),
                actor_id: Some(user.id),
                actor_username: Some(user.username),
                actor_ip: Some(addr.ip()),
                actor_ua: None,
                target_type: Some("user".into()),
                target_id: Some(user.id.to_string()),
                action: "change_password".into(),
                outcome: "success".into(),
                reason: None,
                metadata: None,
            }).await;
            Json(serde_json::json!({"success": true})).into_response()
        }
        Err(e) => {
            tracing::error!("update_password error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}