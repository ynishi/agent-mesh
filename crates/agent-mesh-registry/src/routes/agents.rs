use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration, Capability};
use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId};
use agent_mesh_core::message::KeyRotationRequest;
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
    AuthUser(user_id): AuthUser,
    Query(mut query): Query<AgentCardQuery>,
) -> Result<Json<Vec<AgentCard>>, (StatusCode, String)> {
    // Group-scoped discovery: inject the user's group memberships.
    let groups = state
        .db
        .list_groups_for_user(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let group_ids: Vec<GroupId> = groups.iter().map(|g| g.id).collect();
    query.group_ids = Some(group_ids);

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

/// Response body for `POST /agents/{card_id}/rotate-key`.
#[derive(Serialize)]
pub struct RotateKeyResponse {
    pub card_id: AgentCardId,
    pub old_agent_id: AgentId,
    pub new_agent_id: AgentId,
    pub rotation_expires_at: String,
}

/// Grace period default: 24 hours in seconds.
const DEFAULT_GRACE_PERIOD_SECS: u64 = 86_400;

/// `POST /agents/{card_id}/rotate-key`
///
/// Initiates a key rotation for the given agent card. The caller must be the
/// card's owner and must supply a `KeyRotationProof` signed by the current key.
pub async fn rotate_key(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(card_id_str): Path<String>,
    Json(req): Json<KeyRotationRequest>,
) -> Result<Json<RotateKeyResponse>, (StatusCode, String)> {
    let card_id = AgentCardId::parse_str(&card_id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Path card_id must match body card_id.
    if card_id != req.card_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "card_id in path does not match body".into(),
        ));
    }

    // Verify the cryptographic proof before any DB access.
    req.proof.verify(&req.new_agent_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid rotation proof: {e}"),
        )
    })?;

    // Load the card and enforce ownership.
    let card = state
        .db
        .get_by_id(&card_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "agent not found".into()))?;

    if card.owner_id != user_id {
        return Err((StatusCode::FORBIDDEN, "not the owner".into()));
    }

    // Verify that the proof's old_agent_id matches the card's current agent_id.
    if req.proof.old_agent_id != card.agent_id {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof old_agent_id does not match card's current agent_id".into(),
        ));
    }

    let grace_secs = req.grace_period_secs.unwrap_or(DEFAULT_GRACE_PERIOD_SECS);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(grace_secs as i64);

    state
        .db
        .start_key_rotation(&card_id, &req.new_agent_id, expires_at)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let old_agent_id = card.agent_id;
    Ok(Json(RotateKeyResponse {
        card_id,
        old_agent_id,
        new_agent_id: req.new_agent_id,
        rotation_expires_at: expires_at.to_rfc3339(),
    }))
}

/// Response body for `POST /agents/{card_id}/complete-rotation`.
#[derive(Serialize)]
pub struct CompleteRotationResponse {
    pub card_id: AgentCardId,
    pub old_agent_id: AgentId,
    pub new_agent_id: AgentId,
    pub acl_rules_updated: usize,
}

/// `POST /agents/{card_id}/complete-rotation`
///
/// Completes an in-progress key rotation for the given agent card.
///
/// The caller must be the card's owner. The operation is atomic: the old
/// `agent_id` is replaced by `pending_agent_id`, all ACL rules referencing
/// the old agent ID are rewritten, and a revocation record for the old key
/// is inserted — all in a single SQLite transaction.
///
/// Broadcasts in order: `KeyRotated` → `AclUpdated` → `KeyRevoked`.
pub async fn complete_rotation(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(card_id_str): Path<String>,
) -> Result<Json<CompleteRotationResponse>, (StatusCode, String)> {
    let card_id = AgentCardId::parse_str(&card_id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Enforce ownership.
    let card = state
        .db
        .get_by_id(&card_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "agent not found".into()))?;

    if card.owner_id != user_id {
        return Err((StatusCode::FORBIDDEN, "not the owner".into()));
    }

    // Execute atomic ACL rewrite + agent_id update + revocation insert.
    // complete_key_rotation returns Err if pending_agent_id IS NULL.
    let result = state
        .db
        .complete_key_rotation(&card_id, user_id)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("no rotation in progress") {
                (StatusCode::CONFLICT, msg)
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, msg)
            }
        })?;

    // ── Broadcast in order: KeyRotated → AclUpdated → KeyRevoked ─────────────
    use agent_mesh_core::acl::AclRule;
    use agent_mesh_core::message::KeyRevocation;
    use agent_mesh_core::sync::SyncEvent;

    // 1. KeyRotated — notify meshd that the identity has changed.
    state
        .sync_hub
        .broadcast_to_group(
            &result.group_id,
            &SyncEvent::KeyRotated {
                card_id,
                old_agent_id: result.old_agent_id.clone(),
                new_agent_id: result.new_agent_id.clone(),
            },
        )
        .await;

    // 2. AclUpdated — push the rewritten ACL rules.
    let rule_rows = state
        .db
        .list_acl_rules_for_group(&result.group_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let acl_rules: Vec<AclRule> = rule_rows
        .into_iter()
        .map(|row| {
            let caps: Vec<String> = serde_json::from_str(&row.allowed_capabilities)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(AclRule {
                source: agent_mesh_core::identity::AgentId::from_raw(row.source),
                target: agent_mesh_core::identity::AgentId::from_raw(row.target),
                allowed_capabilities: caps,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    state
        .sync_hub
        .broadcast_to_group(&result.group_id, &SyncEvent::AclUpdated(acl_rules))
        .await;

    // 3. KeyRevoked — notify meshd that the old key must no longer be trusted.
    // SENTINEL: 'cp_rotation' is not a valid Ed25519 signature.
    // meshd must skip verify() for entries with this sentinel (handled in ST3).
    let revocation = KeyRevocation {
        agent_id: result.old_agent_id.clone(),
        reason: Some("key_rotation".to_string()),
        timestamp: chrono::Utc::now().timestamp_millis(),
        signature: "cp_rotation".to_string(),
    };
    state
        .sync_hub
        .broadcast_to_group(&result.group_id, &SyncEvent::KeyRevoked(revocation))
        .await;

    Ok(Json(CompleteRotationResponse {
        card_id,
        old_agent_id: result.old_agent_id,
        new_agent_id: result.new_agent_id,
        acl_rules_updated: result.acl_rules_updated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hash_token;
    use crate::{app, AppState};
    use agent_mesh_core::identity::UserId;
    use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn make_db() -> Arc<crate::db::Database> {
        Arc::new(crate::db::Database::open(":memory:").expect("in-memory db"))
    }

    fn make_app_state(db: Arc<crate::db::Database>) -> AppState {
        AppState {
            db,
            oauth_config: None,
            http_client: reqwest::Client::new(),
            sync_hub: Arc::new(crate::sync::SyncHub::new()),
        }
    }

    /// Create a user, group, member relationship and api_token in DB.
    /// Returns (user_id, group_id, raw_token).
    fn setup_user_group_token(
        db: &Arc<crate::db::Database>,
        external_id: &str,
    ) -> (UserId, GroupId, String) {
        let user = User {
            id: UserId::new_v4(),
            external_id: external_id.to_string(),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        db.create_user(&user).unwrap();

        let group = Group {
            id: GroupId::new_v4(),
            name: format!("group-{external_id}"),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).unwrap();
        db.add_group_member(&GroupMember {
            group_id: group.id,
            user_id: user.id,
            role: GroupRole::Owner,
        })
        .unwrap();

        let raw_token = format!("at_{external_id}_token");
        let token = ApiToken {
            token_hash: hash_token(&raw_token),
            user_id: user.id,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        db.create_api_token(&token).unwrap();

        (user.id, group.id, raw_token)
    }

    #[tokio::test]
    async fn search_agents_returns_only_own_group_agents() {
        let db = make_db();
        let (user1_id, group1_id, token1) = setup_user_group_token(&db, "user1");
        let (user2_id, group2_id, _token2) = setup_user_group_token(&db, "user2");

        // Register an agent for user1's group
        let reg1 = AgentCardRegistration {
            agent_id: AgentId::from_raw("agent-1".to_string()),
            name: "Agent One".to_string(),
            description: None,
            capabilities: vec![],
            metadata: None,
        };
        db.register(&reg1, user1_id, group1_id).unwrap();

        // Register an agent for user2's group
        let reg2 = AgentCardRegistration {
            agent_id: AgentId::from_raw("agent-2".to_string()),
            name: "Agent Two".to_string(),
            description: None,
            capabilities: vec![],
            metadata: None,
        };
        db.register(&reg2, user2_id, group2_id).unwrap();

        let app = app(make_app_state(db));

        // user1 searches: should only see Agent One, not Agent Two
        let req = Request::builder()
            .method("GET")
            .uri("/agents")
            .header("authorization", format!("Bearer {token1}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let cards: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            cards.len(),
            1,
            "user1 should only see agents in their group"
        );
        assert_eq!(cards[0]["name"], "Agent One");
    }

    #[tokio::test]
    async fn search_agents_excludes_other_group_agents() {
        let db = make_db();
        let (_user1_id, group1_id, token1) = setup_user_group_token(&db, "exc-user1");
        let (user2_id, group2_id, _token2) = setup_user_group_token(&db, "exc-user2");

        // user2 registers an agent
        let reg2 = AgentCardRegistration {
            agent_id: AgentId::from_raw("agent-x".to_string()),
            name: "Agent X".to_string(),
            description: None,
            capabilities: vec![],
            metadata: None,
        };
        db.register(&reg2, user2_id, group2_id).unwrap();

        let app = app(make_app_state(db));

        // user1 searches: should see 0 agents (only has group1, and no agents in group1)
        let req = Request::builder()
            .method("GET")
            .uri("/agents")
            .header("authorization", format!("Bearer {token1}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let cards: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(
            cards.is_empty(),
            "user1 must not see agents from group2: {cards:?}"
        );

        // Suppress unused variable warning
        let _ = group1_id;
    }

    // ── rotate_key tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn rotate_key_success() {
        use agent_mesh_core::identity::AgentKeypair;
        use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};

        let db = make_db();
        let (user_id, group_id, token) = setup_user_group_token(&db, "rot-user");

        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();

        let reg = AgentCardRegistration {
            agent_id: old_kp.agent_id(),
            name: "RotAgent".to_string(),
            description: None,
            capabilities: vec![],
            metadata: None,
        };
        let card = db.register(&reg, user_id, group_id).unwrap();

        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        let req_body = KeyRotationRequest {
            card_id: card.id,
            new_agent_id: new_kp.agent_id(),
            proof,
            grace_period_secs: Some(3600),
        };

        let app = app(make_app_state(db));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/rotate-key", card.id))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["new_agent_id"], new_kp.agent_id().as_str());
    }

    #[tokio::test]
    async fn rotate_key_wrong_owner_forbidden() {
        use agent_mesh_core::identity::AgentKeypair;
        use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};

        let db = make_db();
        let (owner_id, group_id, _token_owner) = setup_user_group_token(&db, "ro-owner");
        let (_other_id, _other_group, token_other) = setup_user_group_token(&db, "ro-other");

        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();

        let card = db
            .register(
                &AgentCardRegistration {
                    agent_id: old_kp.agent_id(),
                    name: "OwnedAgent".to_string(),
                    description: None,
                    capabilities: vec![],
                    metadata: None,
                },
                owner_id,
                group_id,
            )
            .unwrap();

        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        let req_body = KeyRotationRequest {
            card_id: card.id,
            new_agent_id: new_kp.agent_id(),
            proof,
            grace_period_secs: None,
        };

        let app = app(make_app_state(db));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/rotate-key", card.id))
                    .header("authorization", format!("Bearer {token_other}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rotate_key_invalid_proof_rejected() {
        use agent_mesh_core::identity::AgentKeypair;
        use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};

        let db = make_db();
        let (user_id, group_id, token) = setup_user_group_token(&db, "bad-proof-user");

        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let wrong_kp = AgentKeypair::generate(); // Proof signed by wrong key.

        let card = db
            .register(
                &AgentCardRegistration {
                    agent_id: old_kp.agent_id(),
                    name: "BadProofAgent".to_string(),
                    description: None,
                    capabilities: vec![],
                    metadata: None,
                },
                user_id,
                group_id,
            )
            .unwrap();

        // Proof signed by `wrong_kp` but old_agent_id claims to be `old_kp`.
        let mut proof = KeyRotationProof::new(&wrong_kp, &new_kp.agent_id());
        proof.old_agent_id = old_kp.agent_id(); // Tamper.

        let req_body = KeyRotationRequest {
            card_id: card.id,
            new_agent_id: new_kp.agent_id(),
            proof,
            grace_period_secs: None,
        };

        let app = app(make_app_state(db));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/rotate-key", card.id))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rotate_key_duplicate_rotation_rejected() {
        use agent_mesh_core::identity::AgentKeypair;
        use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};

        let db = make_db();
        let (user_id, group_id, token) = setup_user_group_token(&db, "dup-rot-user");

        let old_kp = AgentKeypair::generate();
        let new_kp1 = AgentKeypair::generate();
        let new_kp2 = AgentKeypair::generate();

        let card = db
            .register(
                &AgentCardRegistration {
                    agent_id: old_kp.agent_id(),
                    name: "DupRotAgent".to_string(),
                    description: None,
                    capabilities: vec![],
                    metadata: None,
                },
                user_id,
                group_id,
            )
            .unwrap();

        // First rotation — should succeed.
        let proof1 = KeyRotationProof::new(&old_kp, &new_kp1.agent_id());
        let req1 = KeyRotationRequest {
            card_id: card.id,
            new_agent_id: new_kp1.agent_id(),
            proof: proof1,
            grace_period_secs: None,
        };
        let router1 = app(make_app_state(db.clone()));
        let resp1 = router1
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/rotate-key", card.id))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second rotation while first is still pending — should be rejected.
        let proof2 = KeyRotationProof::new(&old_kp, &new_kp2.agent_id());
        let req2 = KeyRotationRequest {
            card_id: card.id,
            new_agent_id: new_kp2.agent_id(),
            proof: proof2,
            grace_period_secs: None,
        };
        let app2 = app(make_app_state(db));
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/agents/{}/rotate-key", card.id))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    }
}
