mod db;
mod routes;

use anyhow::Result;
use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::db::Database;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let db_path = std::env::var("REGISTRY_DB").unwrap_or_else(|_| "registry.db".into());
    let db = Arc::new(Database::open(&db_path)?);

    let addr = std::env::var("REGISTRY_ADDR").unwrap_or_else(|_| "0.0.0.0:9801".into());

    let app = Router::new()
        .route("/agents", post(routes::register_agent))
        .route("/agents", get(routes::search_agents))
        .route("/agents/{id}", get(routes::get_agent))
        .route("/agents/{id}", delete(routes::delete_agent))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(db);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("registry listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
