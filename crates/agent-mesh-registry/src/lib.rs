pub mod auth;
pub mod db;
pub mod routes;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

use crate::db::Database;

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
}

/// Build the registry router with the given state.
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    public.merge(authed).with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
