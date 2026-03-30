mod hub;
mod ws;

use anyhow::Result;
use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::hub::Hub;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let hub = Arc::new(Hub::new());
    hub.start_reaper();
    let addr = std::env::var("RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:9800".into());

    let app = Router::new()
        .route("/ws", get(ws::ws_handler))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .with_state(hub);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("relay listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
