mod hub;
mod ws;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use mesh_proto::message::KeyRevocation;
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
        .route("/revoke", post(revoke_handler))
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

/// POST /revoke — Submit a signed key revocation.
async fn revoke_handler(
    State(hub): State<Arc<Hub>>,
    Json(revocation): Json<KeyRevocation>,
) -> impl IntoResponse {
    match hub.revoke(&revocation).await {
        Ok(()) => (StatusCode::OK, "revoked".to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, e),
    }
}
