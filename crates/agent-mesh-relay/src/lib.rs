//! WebSocket relay server: routes opaque, Noise-encrypted envelopes between
//! connected agents without ever seeing their plaintext payloads.
//!
//! # Architecture
//!
//! The relay only sees message routing metadata (`from`/`to`) on the
//! [`agent_mesh_core::message::MeshEnvelope`] wire type from `agent-mesh-core`;
//! payload confidentiality is enforced end-to-end by the Noise session
//! between the two agents, not by the relay.
//!
//! - [`hub`] — [`hub::Hub`], the central in-memory router: tracks connected
//!   agent WebSocket sessions, buffers messages for offline agents (bounded),
//!   applies per-agent rate limiting, and reaps dead sessions.
//! - [`ws`] — the Axum WebSocket upgrade handler ([`ws::ws_handler`]) that
//!   authenticates an incoming connection and hands it off to [`hub::Hub`].
//! - [`gate`] — [`GateVerifier`], the trait the relay uses to authorize a
//!   connecting agent against the control plane (`agent-mesh-registry`) via
//!   its `/gate/verify` endpoint; decouples the relay from a specific
//!   registry deployment.
//! - [`config`] — [`config::RelayConfig`], process-level configuration.
//!
//! The relay depends on `agent-mesh-core` for identity and envelope types
//! and, at runtime (via [`gate::HttpGateVerifier`]), on an `agent-mesh-registry`
//! deployment reachable over HTTP for connection authorization.
#![warn(missing_docs)]

/// Process-level configuration ([`config::RelayConfig`]), loaded from TOML
/// with defaults for missing fields.
pub mod config;
/// Connection authorization: the [`gate::GateVerifier`] trait and its
/// HTTP-backed / noop implementations.
pub mod gate;
/// The central in-memory router ([`hub::Hub`]) that tracks connected
/// sessions, buffers offline messages, and rate-limits per agent.
pub mod hub;
/// Axum WebSocket upgrade handler and the auth/routing loop for a single
/// connection.
pub mod ws;

pub use gate::GateVerifier;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::hub::Hub;

/// Build the relay Router with the given Hub state.
pub fn app(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/ws", get(ws::ws_handler))
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(hub)
}

async fn health() -> &'static str {
    "ok"
}

async fn metrics_handler(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    let connected = hub.connected_count().await;
    let buffered = hub.buffered_agent_count().await;
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
