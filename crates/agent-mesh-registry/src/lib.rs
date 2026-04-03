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
///   the Setup Key directly inside the handler (architecture.md §11.1,
///   BP: Tailscale/NetBird). No auth middleware is applied here intentionally.
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

    // Setup Key registration endpoint: no Bearer auth middleware.
    // The handler verifies the Setup Key directly (architecture.md §11.1).
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
