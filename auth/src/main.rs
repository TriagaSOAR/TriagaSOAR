// auth/src/main.rs
mod crypto;
mod db;
mod middleware;
mod proxy;
mod routes;
mod totp;

use anyhow::Result;
use axum::{Router, middleware as axum_middleware};
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub audit_db: sqlx::PgPool,
    pub config: Arc<Config>,
}

#[derive(Debug)]
pub struct Config {
    pub database_url: String,
    pub audit_database_url: String,
    pub backend_url: String,
    pub agent_url: String,
    pub session_secret: String,
    pub admin_password: String,
    pub admin_email: String,
    pub ip_allowlist: Vec<std::net::IpAddr>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let postgres_host = std::env::var("POSTGRES_HOST").unwrap_or("localhost".into());
        let postgres_port = std::env::var("POSTGRES_PORT").unwrap_or("5432".into());
        let postgres_db = std::env::var("POSTGRES_DB").unwrap_or("soc_triage".into());
        let auth_app_password = std::env::var("AUTH_APP_PASSWORD")?;
        let audit_writer_password = std::env::var("AUDIT_WRITER_PASSWORD")?;

        let database_url = format!(
            "postgres://auth_app:{auth_app_password}@{postgres_host}:{postgres_port}/{postgres_db}"
        );
        let audit_database_url = format!(
            "postgres://audit_writer:{audit_writer_password}@{postgres_host}:{postgres_port}/{postgres_db}"
        );

        let ip_allowlist: Vec<std::net::IpAddr> = std::env::var("IP_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        Ok(Config {
            database_url,
            audit_database_url,
            backend_url: std::env::var("BACKEND_URL").unwrap_or("http://localhost:3000".into()),
            agent_url: std::env::var("AGENT_URL").unwrap_or("http://localhost:8000".into()),
            session_secret: std::env::var("SESSION_SECRET")
                .unwrap_or_else(|_| crypto::generate_token_hex()),
            admin_password: std::env::var("ADMIN_PASSWORD").unwrap_or_default(),
            admin_email: std::env::var("ADMIN_EMAIL").unwrap_or_default(),
            ip_allowlist,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "soc_auth=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(Config::from_env()?);

    tracing::info!("Connecting to database...");
    let db = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await?;

    let audit_db = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.audit_database_url)
        .await?;

    tracing::info!("Skipping compile-time migrations — using runtime schema");

    let state = AppState {
        db: db.clone(),
        audit_db: audit_db.clone(),
        config: config.clone(),
    };

    db::users::ensure_admin(&db, &config).await?;

    let app = Router::new()
        .nest("/auth", routes::auth_router())
        .nest("/sat", routes::sat_router())
        .nest("/audit", routes::audit_router())
        .fallback(proxy::proxy_handler)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::GATEWAY_TIMEOUT, Duration::from_secs(30)))
                .layer(axum_middleware::from_fn_with_state(
                    state.clone(),
                    middleware::session::session_middleware,
                ))
                .layer(axum_middleware::from_fn_with_state(
                    state.clone(),
                    middleware::ratelimit::rate_limit_middleware,
                ))
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 4000));
    tracing::info!("Auth proxy listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}