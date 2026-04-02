use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::AppState;

/// Request body for verifying an agent's group membership.
#[derive(Deserialize)]
pub struct VerifyAgentRequest {
    /// Agent ID to look up (string form).
    pub agent_id: String,
}

/// Response when the agent is found.
#[derive(Serialize)]
pub struct VerifyAgentResponse {
    pub group_id: String,
}

/// `POST /gate/verify` — internal Relay API: verify that an agent_id is registered
/// and return its group_id.
///
/// Returns 200 + `{ "group_id": "<uuid>" }` if found, 404 otherwise.
/// Protected by the same Bearer token auth as other authed routes (v0.2 shared token).
pub async fn verify_agent(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
    Json(req): Json<VerifyAgentRequest>,
) -> Result<Json<VerifyAgentResponse>, (StatusCode, String)> {
    let group_id = state
        .db
        .get_agent_group_id(&req.agent_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match group_id {
        Some(gid) => Ok(Json(VerifyAgentResponse {
            group_id: gid.0.to_string(),
        })),
        None => Err((StatusCode::NOT_FOUND, "agent not found".into())),
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::hash_token;
    use crate::{app, AppState};
    use agent_mesh_core::agent_card::AgentCardRegistration;
    use agent_mesh_core::identity::{AgentId, UserId};
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

    fn setup_user_group_token(
        db: &Arc<crate::db::Database>,
        external_id: &str,
    ) -> (UserId, agent_mesh_core::identity::GroupId, String) {
        let user = User {
            id: UserId::new_v4(),
            external_id: external_id.to_string(),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        db.create_user(&user).unwrap();

        let group = Group {
            id: agent_mesh_core::identity::GroupId::new_v4(),
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

        let raw_token = format!("at_{external_id}_tok");
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
    async fn verify_agent_found_returns_200() {
        let db = make_db();
        let (uid, gid, token) = setup_user_group_token(&db, "gate-u1");

        db.register(
            &AgentCardRegistration {
                agent_id: AgentId::from_raw("gate-agent-1".to_string()),
                name: "Gate Agent".to_string(),
                description: None,
                capabilities: vec![],
                metadata: None,
            },
            uid,
            gid,
        )
        .unwrap();

        let app = app(make_app_state(db));

        let body = serde_json::json!({ "agent_id": "gate-agent-1" });
        let req = Request::builder()
            .method("POST")
            .uri("/gate/verify")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["group_id"], gid.0.to_string());
    }

    #[tokio::test]
    async fn verify_agent_not_found_returns_404() {
        let db = make_db();
        let (_uid, _gid, token) = setup_user_group_token(&db, "gate-u2");
        let app = app(make_app_state(db));

        let body = serde_json::json!({ "agent_id": "unknown-agent" });
        let req = Request::builder()
            .method("POST")
            .uri("/gate/verify")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn gate_verify_requires_auth() {
        let db = make_db();
        let app = app(make_app_state(db));

        let body = serde_json::json!({ "agent_id": "any-agent" });
        let req = Request::builder()
            .method("POST")
            .uri("/gate/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
