use std::collections::HashSet;

use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::AppState;

pub async fn register_agent(
    State(state): State<AppState>,
    Json(reg): Json<AgentCardRegistration>,
) -> Result<(StatusCode, Json<AgentCard>), (StatusCode, String)> {
    let card = state
        .db
        .register(&reg)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(card)))
}

pub async fn get_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AgentCard>, (StatusCode, String)> {
    let uuid = Uuid::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    match state
        .db
        .get_by_id(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        Some(card) => Ok(Json(card)),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

pub async fn search_agents(
    State(state): State<AppState>,
    Query(query): Query<AgentCardQuery>,
) -> Result<Json<Vec<AgentCard>>, (StatusCode, String)> {
    let mut cards = state
        .db
        .search(&query)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Enrich with liveness data from relay if configured.
    if let Some(ref relay_url) = state.relay_url {
        if let Ok(online_set) = fetch_online_agents(relay_url).await {
            for card in &mut cards {
                card.online = Some(online_set.contains(card.agent_id.as_str()));
            }
        }
    }

    Ok(Json(cards))
}

pub async fn update_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(reg): Json<AgentCardRegistration>,
) -> Result<Json<AgentCard>, (StatusCode, String)> {
    let uuid = Uuid::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    match state
        .db
        .update(&uuid, &reg)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        Some(card) => Ok(Json(card)),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

pub async fn delete_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let uuid = Uuid::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let deleted = state
        .db
        .delete(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "agent not found".into()))
    }
}

/// Fetch the set of currently online agent IDs from the relay's /status endpoint.
async fn fetch_online_agents(relay_url: &str) -> Result<HashSet<String>, ()> {
    let resp = reqwest::Client::new()
        .get(format!("{relay_url}/status"))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .map_err(|_| ())?;

    let body: serde_json::Value = resp.json().await.map_err(|_| ())?;
    let agents = body
        .get("agents")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(agents)
}
