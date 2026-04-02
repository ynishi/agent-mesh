pub mod auth;
pub mod db;
pub mod routes;

use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

use crate::db::Database;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
}

/// Build the registry router with the given state.
pub fn app(state: AppState) -> Router {
    let public = Router::new().route("/health", get(health));

    let authed = Router::new()
        .route("/agents", post(routes::agents::register_agent))
        .route("/agents", get(routes::agents::search_agents))
        .route("/agents/{id}", get(routes::agents::get_agent))
        .route("/agents/{id}", put(routes::agents::update_agent))
        .route("/agents/{id}", delete(routes::agents::delete_agent))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    public.merge(authed).with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
