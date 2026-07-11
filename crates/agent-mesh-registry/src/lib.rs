//! Control-plane HTTP API: Agent Card registry, capability search, and
//! account/authorization management for agent-mesh.
//!
//! # Architecture
//!
//! `agent-mesh-registry` is the "control plane" in the mesh — it does not
//! route agent-to-agent traffic (that is `agent-mesh-relay`'s job); it holds
//! the durable state the rest of the network needs to establish trust:
//!
//! - [`db`] — [`db::Database`], a SQLite-backed store (via `rusqlite`) for
//!   users, groups, agent cards, ACL rules, setup keys, and key revocations.
//! - [`routes`] — HTTP handlers for OAuth device-flow login, agent
//!   registration/discovery, group and ACL management, and gate
//!   verification. Split across sub-modules per resource (`agents`, `groups`,
//!   `acl`, `setup_keys`, `revocations`, `oauth`, `gate`, `status`).
//! - [`auth`] — [`auth::require_auth`] Bearer-token middleware and token
//!   hashing shared by the authenticated route layer.
//! - [`sync`] — [`sync::SyncHub`] WebSocket endpoint that pushes
//!   `agent_mesh_core::sync::SyncMessage` state snapshots to connected
//!   `agent-meshd` instances as state changes.
//!
//! [`app`] assembles three router layers with different auth requirements:
//! `public` (no auth), `authed` (Bearer token via [`auth::require_auth`]),
//! and `setup_key_routes` (verifies a Setup Key inline in the handler
//! instead of via middleware — see [`routes::agents::register_with_setup_key`]
//! for the rationale). This crate depends on `agent-mesh-core` for all wire
//! and identity types; it does not depend on `agent-mesh-relay` or
//! `agent-meshd` — the dependency runs the other way, over HTTP/WebSocket:
//! `agent-mesh-relay` calls this crate's `/gate/verify` endpoint to
//! authorize connecting agents, and `agent-meshd` calls it for registration
//! and state sync.
pub mod auth;
pub mod db;
pub mod routes;
pub mod sync;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

use crate::db::Database;
use crate::sync::SyncHub;

/// OAuth provider configuration for Device Flow authentication.
#[derive(Clone)]
pub struct OAuthConfig {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub device_code_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

impl OAuthConfig {
    /// Build an OAuthConfig from a provider name, client_id, and client_secret.
    /// Currently only "github" is supported.
    pub fn from_provider(
        provider: String,
        client_id: String,
        client_secret: String,
    ) -> anyhow::Result<Self> {
        match provider.as_str() {
            "github" => Ok(Self {
                provider,
                client_id,
                client_secret,
                device_code_url: "https://github.com/login/device/code".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                userinfo_url: "https://api.github.com/user".to_string(),
            }),
            other => anyhow::bail!("unsupported OAuth provider: {other}"),
        }
    }
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub oauth_config: Option<OAuthConfig>,
    pub http_client: reqwest::Client,
    pub sync_hub: Arc<SyncHub>,
}

/// Build the registry router with the given state.
///
/// The router is organized into three layers:
/// - `public`: no authentication required (health, oauth)
/// - `authed`: requires Bearer token via `require_auth` middleware
/// - `setup_key_routes`: Setup Key endpoints — `/register-with-key` verifies
///   the Setup Key directly inside the handler. No auth middleware is
///   applied here intentionally: the caller does not have a Bearer token
///   yet (registration *produces* one), so `require_auth` cannot run first.
///   This mirrors Tailscale's Auth Key and NetBird's Setup Key, which are
///   likewise verified inline by the registration endpoint rather than by a
///   generic auth layer.
pub fn app(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/oauth/device", post(routes::oauth::start_device_flow))
        .route("/oauth/token", post(routes::oauth::exchange_token));

    let authed = Router::new()
        .route("/agents", post(routes::agents::register_agent))
        .route("/agents", get(routes::agents::search_agents))
        .route("/agents/{id}", get(routes::agents::get_agent))
        .route("/agents/{id}", put(routes::agents::update_agent))
        .route("/agents/{id}", delete(routes::agents::delete_agent))
        .route("/users/me", get(routes::users::get_me))
        .route("/groups", post(routes::groups::create_group))
        .route("/groups", get(routes::groups::list_groups))
        .route("/groups/{id}/members", post(routes::groups::add_member))
        .route(
            "/groups/{id}/members/{user_id}",
            delete(routes::groups::remove_member),
        )
        .route(
            "/setup-keys",
            post(routes::setup_keys::create_setup_key).get(routes::setup_keys::list_setup_keys),
        )
        .route(
            "/setup-keys/{id}",
            delete(routes::setup_keys::revoke_setup_key),
        )
        .route(
            "/acl",
            post(routes::acl::create_rule).get(routes::acl::list_rules),
        )
        .route("/acl/{id}", delete(routes::acl::delete_rule))
        .route(
            "/revocations",
            post(routes::revocations::revoke_key).get(routes::revocations::list_revocations),
        )
        .route("/status", get(routes::status::get_status))
        .route("/gate/verify", post(routes::gate::verify_agent))
        .route("/sync", get(sync::ws_handler))
        .route("/agents/{id}/rotate-key", post(routes::agents::rotate_key))
        .route(
            "/agents/{id}/complete-rotation",
            post(routes::agents::complete_rotation),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    // Setup Key registration endpoint: no Bearer auth middleware, since the
    // Setup Key itself is what the caller is exchanging for a Bearer token.
    // The handler verifies the Setup Key directly instead.
    let setup_key_routes = Router::new().route(
        "/register-with-key",
        post(routes::agents::register_with_setup_key),
    );

    public
        .merge(authed)
        .merge(setup_key_routes)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
