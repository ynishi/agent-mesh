use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration, Capability};
use agent_mesh_core::identity::{AgentCardId, AgentId};
use agent_mesh_core::user::ApiToken;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::auth::{hash_token, AuthUser};
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

/// Request body for registering an agent with a Setup Key.
/// Setup Key verification is done inside the handler (not middleware).
/// Architecture decision: architecture.md §11.1 — BP: Tailscale/NetBird.
#[derive(Deserialize)]
pub struct RegisterWithSetupKeyRequest {
    /// Plaintext setup key (e.g. `sk_...`).
    pub setup_key: String,
    pub agent_id: AgentId,
    pub name: String,
    pub capabilities: Vec<Capability>,
}

/// Response for registering an agent with a Setup Key.
#[derive(Serialize)]
pub struct RegisterWithSetupKeyResponse {
    pub agent_card: AgentCard,
    /// Plaintext ApiToken — shown only once at registration.
    pub api_token: String,
}

/// Generate a raw API token: `at_` prefix + 32 random bytes as hex.
fn generate_raw_api_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("at_{hex}")
}

/// Register an agent using a plaintext Setup Key.
///
/// Setup Key verification is performed directly in this handler
/// (architecture.md §11.1). This endpoint lives in the third router layer
/// (`setup_key_routes`) which has no Bearer auth middleware.
pub async fn register_with_setup_key(
    State(state): State<AppState>,
    Json(req): Json<RegisterWithSetupKeyRequest>,
) -> Result<(StatusCode, Json<RegisterWithSetupKeyResponse>), (StatusCode, String)> {
    // Hash the plaintext setup key and verify it.
    let key_hash = hash_token(&req.setup_key);
    let setup_key = state
        .db
        .verify_setup_key(&key_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid or expired setup key".to_string(),
        ))?;

    let reg = AgentCardRegistration {
        agent_id: req.agent_id,
        name: req.name,
        description: None,
        capabilities: req.capabilities,
        metadata: None,
    };

    let card = state
        .db
        .register(&reg, setup_key.user_id, setup_key.group_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Issue a new ApiToken for the registered agent's owner.
    let raw_token = generate_raw_api_token();
    let token = ApiToken {
        token_hash: hash_token(&raw_token),
        user_id: setup_key.user_id,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    state
        .db
        .create_api_token(&token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterWithSetupKeyResponse {
            agent_card: card,
            api_token: raw_token,
        }),
    ))
}
