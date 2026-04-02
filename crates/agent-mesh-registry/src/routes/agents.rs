use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use agent_mesh_core::identity::AgentCardId;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::AuthUser;
use crate::AppState;

pub async fn register_agent(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(reg): Json<AgentCardRegistration>,
) -> Result<(StatusCode, Json<AgentCard>), (StatusCode, String)> {
    let group_id = state
        .db
        .ensure_user_has_group(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let card = state
        .db
        .register(&reg, user_id, group_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(card)))
}

pub async fn get_agent(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AgentCard>, (StatusCode, String)> {
    let id = AgentCardId::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    match state
        .db
        .get_by_id(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        Some(card) => Ok(Json(card)),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

pub async fn search_agents(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
    Query(query): Query<AgentCardQuery>,
) -> Result<Json<Vec<AgentCard>>, (StatusCode, String)> {
    let cards = state
        .db
        .search(&query)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(cards))
}

pub async fn update_agent(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<String>,
    Json(reg): Json<AgentCardRegistration>,
) -> Result<Json<AgentCard>, (StatusCode, String)> {
    let id = AgentCardId::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let card = state
        .db
        .get_by_id(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "agent not found".into()))?;

    if card.owner_id != user_id {
        return Err((StatusCode::FORBIDDEN, "not the owner".into()));
    }

    match state
        .db
        .update(&id, &reg)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        Some(updated) => Ok(Json(updated)),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

pub async fn delete_agent(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = AgentCardId::parse_str(&id).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let card = state
        .db
        .get_by_id(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "agent not found".into()))?;

    if card.owner_id != user_id {
        return Err((StatusCode::FORBIDDEN, "not the owner".into()));
    }

    let deleted = state
        .db
        .delete(&id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "agent not found".into()))
    }
}
