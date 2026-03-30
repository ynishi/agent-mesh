use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use mesh_proto::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use uuid::Uuid;

use crate::db::Database;

pub async fn register_agent(
    State(db): State<Arc<Database>>,
    Json(reg): Json<AgentCardRegistration>,
) -> Result<(StatusCode, Json<AgentCard>), (StatusCode, String)> {
    let card = db
        .register(&reg)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(card)))
}

pub async fn get_agent(
    State(db): State<Arc<Database>>,
    Path(id): Path<String>,
) -> Result<Json<AgentCard>, (StatusCode, String)> {
    let uuid = Uuid::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    match db
        .get_by_id(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        Some(card) => Ok(Json(card)),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

pub async fn search_agents(
    State(db): State<Arc<Database>>,
    Query(query): Query<AgentCardQuery>,
) -> Result<Json<Vec<AgentCard>>, (StatusCode, String)> {
    let cards = db
        .search(&query)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(cards))
}

pub async fn delete_agent(
    State(db): State<Arc<Database>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let uuid = Uuid::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let deleted = db
        .delete(&uuid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "agent not found".into()))
    }
}
