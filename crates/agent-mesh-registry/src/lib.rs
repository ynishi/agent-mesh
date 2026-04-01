pub mod db;
pub mod routes;

use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

use crate::db::Database;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    /// Optional relay URL for liveness enrichment.
    pub relay_url: Option<String>,
}

/// Build the registry router with the given state.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/agents", post(routes::register_agent))
        .route("/agents", get(routes::search_agents))
        .route("/agents/{id}", get(routes::get_agent))
        .route("/agents/{id}", put(routes::update_agent))
        .route("/agents/{id}", delete(routes::delete_agent))
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
