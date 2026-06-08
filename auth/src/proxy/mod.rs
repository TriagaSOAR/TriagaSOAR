// auth/src/proxy/mod.rs
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use crate::AppState;

pub async fn proxy_handler(
    State(state): State<AppState>,
    mut request: Request,
) -> Response {
    let path = request.uri().path();
    let query = request.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();

    // Route /api/* to soc-agent (strip /api prefix)
    // Everything else goes to web-backend
    let target_url = if path.starts_with("/api/") {
        let stripped = path.strip_prefix("/api").unwrap_or(path);
        format!("{}{}{}", state.config.agent_url, stripped, query)
    } else {
        format!("{}{}{}", state.config.backend_url, path, query)
    };

    let uri: Uri = match target_url.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid proxy URI: {}", e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    *request.uri_mut() = uri;

    request.headers_mut().insert(
        "x-soc-authenticated",
        HeaderValue::from_static("true"),
    );

    let client: Client<_, Body> = Client::builder(TokioExecutor::new()).build_http();

    match client.request(request).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body = Body::new(body.map_err(|e| {
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            }));
            Response::from_parts(parts, body)
        }
        Err(e) => {
            tracing::error!("Proxy error: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}