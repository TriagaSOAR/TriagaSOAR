// auth/src/routes/sat.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use crate::{AppState, db};
use crate::db::sessions::Session;

#[derive(Deserialize)]
pub struct IssueTokenRequest {
    pub action_type: String,
    pub target: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct IssueTokenResponse {
    pub token: String,
    pub expires_in_seconds: u64,
    pub action_type: String,
    pub target: String,
}

#[derive(Deserialize)]
pub struct ConsumeTokenRequest {
    pub token: String,
    pub action_type: String,
    pub target: String,
}

/// Issue a single-action token.
/// Requires L3 session. Reason must be >= 20 chars.
pub async fn issue_sat(
    State(state): State<AppState>,
    axum::Extension(session): axum::Extension<Session>,
    Json(body): Json<IssueTokenRequest>,
) -> Response {
    if body.reason.len() < 20 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "reason must be at least 20 characters"
            })),
        ).into_response();
    }

    // Validate action type
    let valid_actions = [
        "disable_user", "enable_user", "revoke_sessions",
        "suspend_user", "unsuspend_user", "deactivate_user",
        "clear_sessions", "block_user", "unblock_user",
    ];
    if !valid_actions.contains(&body.action_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid action_type"})),
        ).into_response();
    }

    match db::tokens::issue(
        &state.db,
        session.user_id,
        session.id,
        &body.action_type,
        &body.target,
        &body.reason,
    ).await {
        Ok(token) => {
            // Audit
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "sat.issued".into(),
                actor_id: Some(session.user_id),
                actor_username: None,
                actor_ip: None,
                actor_ua: None,
                target_type: Some("action_token".into()),
                target_id: Some(body.target.clone()),
                action: body.action_type.clone(),
                outcome: "success".into(),
                reason: Some(body.reason.clone()),
                metadata: None,
            }).await;

            Json(IssueTokenResponse {
                token,
                expires_in_seconds: 60,
                action_type: body.action_type,
                target: body.target,
            }).into_response()
        }
        Err(e) => {
            tracing::error!("SAT issue error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Consume a SAT — called by the frontend before executing a response action.
pub async fn consume_sat(
    State(state): State<AppState>,
    axum::Extension(session): axum::Extension<Session>,
    Json(body): Json<ConsumeTokenRequest>,
) -> Response {
    match db::tokens::consume(&state.db, &body.token, &body.action_type, &body.target).await {
        Ok(Some(sat)) => {
            let _ = db::audit::append(&state.audit_db, db::audit::AuditEntry {
                event_type: "sat.consumed".into(),
                actor_id: Some(session.user_id),
                actor_username: None,
                actor_ip: None,
                actor_ua: None,
                target_type: Some("action_token".into()),
                target_id: Some(body.target.clone()),
                action: body.action_type.clone(),
                outcome: "success".into(),
                reason: Some(sat.reason.clone()),
                metadata: None,
            }).await;

            Json(serde_json::json!({
                "valid": true,
                "action_type": sat.action_type,
                "target": sat.target,
                "reason": sat.reason,
            })).into_response()
        }
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"valid": false, "error": "token invalid, expired, or already consumed"})),
        ).into_response(),
        Err(e) => {
            tracing::error!("SAT consume error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}