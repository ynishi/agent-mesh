mod hub;
mod ws;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use mesh_proto::message::KeyRevocation;
use std::sync::atomic::Ordering;
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
        .route("/status", get(status_handler))
        .route("/revoke", post(revoke_handler))
        .route("/metrics", get(metrics_handler))
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

/// GET /status — Relay status snapshot.
async fn status_handler(State(hub): State<Arc<Hub>>) -> Json<serde_json::Value> {
    let connected = hub.connected_count().await;
    let buffered = hub.buffered_agent_count().await;
    let revoked = hub.revoked_count().await;
    let agents = hub.connected_agent_ids().await;
    Json(serde_json::json!({
        "connected_agents": connected,
        "buffered_agents": buffered,
        "revoked_agents": revoked,
        "agents": agents,
    }))
}

/// GET /metrics — Prometheus-compatible metrics.
async fn metrics_handler(State(hub): State<Arc<Hub>>) -> String {
    let connected = hub.connected_count().await;
    let buffered = hub.buffered_agent_count().await;
    let revoked = hub.revoked_count().await;
    let routed = hub.messages_routed.load(Ordering::Relaxed);
    let buffered_total = hub.messages_buffered.load(Ordering::Relaxed);
    let dropped = hub.messages_dropped.load(Ordering::Relaxed);
    let rate_limited = hub.messages_rate_limited.load(Ordering::Relaxed);
    let auth_ok = hub.auth_successes.load(Ordering::Relaxed);
    let auth_fail = hub.auth_failures.load(Ordering::Relaxed);

    format!(
        "# HELP mesh_connected_agents Number of currently connected agents.\n\
         # TYPE mesh_connected_agents gauge\n\
         mesh_connected_agents {connected}\n\
         # HELP mesh_buffered_agents Number of agents with buffered messages.\n\
         # TYPE mesh_buffered_agents gauge\n\
         mesh_buffered_agents {buffered}\n\
         # HELP mesh_revoked_agents Number of revoked agent keys.\n\
         # TYPE mesh_revoked_agents gauge\n\
         mesh_revoked_agents {revoked}\n\
         # HELP mesh_messages_routed_total Total messages delivered directly.\n\
         # TYPE mesh_messages_routed_total counter\n\
         mesh_messages_routed_total {routed}\n\
         # HELP mesh_messages_buffered_total Total messages buffered for offline agents.\n\
         # TYPE mesh_messages_buffered_total counter\n\
         mesh_messages_buffered_total {buffered_total}\n\
         # HELP mesh_messages_dropped_total Total messages dropped (buffer full).\n\
         # TYPE mesh_messages_dropped_total counter\n\
         mesh_messages_dropped_total {dropped}\n\
         # HELP mesh_messages_rate_limited_total Total messages rejected by rate limiter.\n\
         # TYPE mesh_messages_rate_limited_total counter\n\
         mesh_messages_rate_limited_total {rate_limited}\n\
         # HELP mesh_auth_successes_total Total successful authentications.\n\
         # TYPE mesh_auth_successes_total counter\n\
         mesh_auth_successes_total {auth_ok}\n\
         # HELP mesh_auth_failures_total Total failed authentications.\n\
         # TYPE mesh_auth_failures_total counter\n\
         mesh_auth_failures_total {auth_fail}\n"
    )
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
