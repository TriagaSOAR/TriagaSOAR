// auth/src/routes/mod.rs
pub mod login;
pub mod sat;
pub mod users;

use axum::{routing::{get, post, delete}, Router};
use crate::AppState;

pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login::login))
        .route("/logout", post(login::logout))
        .route("/health", get(health))
}

pub fn sat_router() -> Router<AppState> {
    Router::new()
        .route("/issue", post(sat::issue_sat))
        .route("/consume", post(sat::consume_sat))
}

pub fn audit_router() -> Router<AppState> {
    Router::new()
        .route("/", get(audit_log))
        .route("/verify", get(verify_chain))
}

pub fn users_router() -> Router<AppState> {
    Router::new()
        .route("/", get(users::list_users).post(users::create_user))
        .route("/{id}", delete(users::deactivate_user))
        .route("/change-password", post(users::change_password))
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status": "ok", "service": "soc-auth"}))
}

async fn audit_log(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let limit = params.get("limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(50);
    let offset = params.get("offset").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);

    match crate::db::audit::recent(&state.audit_db, limit, offset).await {
        Ok(entries) => axum::Json(serde_json::json!({"entries": entries})).into_response(),
        Err(e) => {
            tracing::error!("Audit log error: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn verify_chain(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match crate::db::audit::verify_chain(&state.audit_db).await {
        Ok((total, broken_at)) => axum::Json(serde_json::json!({
            "total": total,
            "intact": broken_at.is_none(),
            "broken_at": broken_at,
        })).into_response(),
        Err(e) => {
            tracing::error!("Chain verify error: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}