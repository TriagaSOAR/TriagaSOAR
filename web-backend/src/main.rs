use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
    routing::get,
};
use bytes::Bytes;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    soc_agent_url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let soc_agent_url = std::env::var("SOC_AGENT_URL")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    info!("Proxying to soc-agent at {}", soc_agent_url);

    let state = Arc::new(AppState {
        client: reqwest::Client::new(),
        soc_agent_url,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .fallback(proxy_handler)
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("web-backend listening on port 3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response<Body>, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let url = format!("{}{}", state.soc_agent_url, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));

    let mut req_builder = state.client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            &url,
        )
        .body(body_bytes);

    // Forward relevant headers
    for (key, value) in &headers {
        let name = key.as_str();
        if name == "content-type" || name == "accept" || name == "authorization" {
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(name, v);
            }
        }
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Proxy error: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    let status = resp.status().as_u16();
    let resp_headers = resp.headers().clone();
    let resp_bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response = Response::builder()
        .status(status);

    // Forward content-type header
    if let Some(ct) = resp_headers.get("content-type") {
        if let Ok(v) = ct.to_str() {
            response = response.header("content-type", v);
        }
    }

    response
        .body(Body::from(resp_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}