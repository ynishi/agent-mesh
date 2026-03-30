mod db;
mod routes;

use anyhow::Result;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::db::Database;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    /// Optional relay URL for liveness enrichment.
    pub relay_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let db_path = std::env::var("REGISTRY_DB").unwrap_or_else(|_| "registry.db".into());
    let db = Arc::new(Database::open(&db_path)?);
    let relay_url = std::env::var("RELAY_URL").ok();

    if let Some(ref url) = relay_url {
        tracing::info!(relay = %url, "liveness enrichment enabled");
    }

    let addr = std::env::var("REGISTRY_ADDR").unwrap_or_else(|_| "0.0.0.0:9801".into());

    let state = AppState { db, relay_url };

    let app = Router::new()
        .route("/agents", post(routes::register_agent))
        .route("/agents", get(routes::search_agents))
        .route("/agents/{id}", get(routes::get_agent))
        .route("/agents/{id}", put(routes::update_agent))
        .route("/agents/{id}", delete(routes::delete_agent))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("registry listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
