// auth/src/middleware/ratelimit.rs
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::IpAddr;
use crate::AppState;

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    if !path.starts_with("/auth/login") {
        return next.run(request).await;
    }

    let ip = extract_ip(&request);

    // Check IP allowlist — if configured, only allow listed IPs
    if !state.config.ip_allowlist.is_empty() {
        let allowed = state.config.ip_allowlist.contains(&ip);
        if !allowed {
            tracing::warn!("Blocked request from non-allowlisted IP: {}", ip);
            return (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"forbidden","message":"IP not in allowlist"}"#,
            ).into_response();
        }
    }

    next.run(request).await
}

fn extract_ip(request: &Request) -> IpAddr {
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            if let Ok(ip) = val.split(',').next().unwrap_or("").trim().parse() {
                return ip;
            }
        }
    }
    "127.0.0.1".parse().unwrap()
}