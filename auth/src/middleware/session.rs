// auth/src/middleware/session.rs
use axum::{

    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::IpAddr;
use crate::{AppState, db};

// Routes that don't require a session
const PUBLIC_PATHS: &[&str] = &[
    "/auth/login",
    "/auth/totp",
    "/auth/health",
];

// Routes that require L2 (investigate)
const L2_PATHS: &[&str] = &[
    "/api/investigate",
    "/api/splunk/query",
    "/api/triage",
];

// Routes that require L3 (respond) — SAT also required
const L3_PATHS: &[&str] = &[
    "/api/entra/actions",
    "/api/okta/actions",
    "/api/auth0/actions",
];

pub async fn session_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Allow public paths
    if PUBLIC_PATHS.iter().any(|p| path.starts_with(p)) {
        return next.run(request).await;
    }

    // Extract session token from cookie
    let token = extract_session_token(&request);
    let token = match token {
        Some(t) => t,
        None => return unauthorized("No session token"),
    };

    // Extract IP
    let ip = extract_ip(&request);
    let ip_str = ip.to_string();

    // Extract user agent
    let ua = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Validate session
    let session = match db::sessions::validate(&state.db, &token, ip, &ua).await {
        Ok(Some(s)) => s,
        Ok(None) => return unauthorized("Invalid or expired session"),
        Err(e) => {
            tracing::error!("Session validation error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Check L3 expiry — drop back to L2 if window expired
    let effective_level = if session.auth_level == 3 {
        match session.level3_expires_at {
            Some(exp) if exp < time::OffsetDateTime::now_utc() => 2,
            None => 2,
            _ => 3,
        }
    } else {
        session.auth_level
    };

    // Enforce minimum auth level for protected paths
    if L3_PATHS.iter().any(|p| path.starts_with(p)) && effective_level < 3 {
        return forbidden("Level 3 authentication required for response actions");
    }
    if L2_PATHS.iter().any(|p| path.starts_with(p)) && effective_level < 2 {
        return forbidden("Level 2 authentication required");
    }

    // Inject session info as request extensions for downstream handlers
    request.extensions_mut().insert(session);

    next.run(request).await
}

fn extract_session_token(request: &Request) -> Option<String> {
    let cookies = request.headers().get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookies.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("soc_session=") {
            return Some(value.to_string());
        }
    }
    None
}

fn extract_ip(request: &Request) -> IpAddr {
    // Try X-Forwarded-For first (if behind a trusted proxy)
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            if let Ok(ip) = val.split(',').next().unwrap_or("").trim().parse() {
                return ip;
            }
        }
    }
    // Fall back to a default
    "127.0.0.1".parse().unwrap()
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"unauthorized","message":"{}"}}"#, msg),
    )
        .into_response()
}

fn forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"forbidden","message":"{}"}}"#, msg),
    )
        .into_response()
}