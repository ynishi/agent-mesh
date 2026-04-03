use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::AuthUser;
use crate::AppState;

/// Registry status response.
#[derive(Serialize)]
pub struct StatusResponse {
    /// Number of agent cards registered in the database.
    pub agent_count: usize,
    /// Number of agents currently connected via WebSocket sync.
    /// Reflects SyncHub.online_agents().len() at request time.
    pub connected_agents: usize,
}

/// `GET /status` — return registry status.
pub async fn get_status(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    let agent_count = state
        .db
        .count_agent_cards()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let connected_agents = state.sync_hub.online_agents().len();

    Ok(Json(StatusResponse {
        agent_count,
        connected_agents,
    }))
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
    async fn status_empty_registry() {
        let db = make_db();
        let (_uid, _gid, token) = setup_user_group_token(&db, "status-u1");
        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["agent_count"], 0);
        // No WS connections in unit test: connected_agents reflects SyncHub.online_agents().len() = 0.
        assert_eq!(val["connected_agents"], 0);
    }

    #[tokio::test]
    async fn status_reflects_registered_agents() {
        let db = make_db();
        let (uid, gid, token) = setup_user_group_token(&db, "status-u2");

        db.register(
            &AgentCardRegistration {
                agent_id: AgentId::from_raw("status-agent-1".to_string()),
                name: "Agent 1".to_string(),
                description: None,
                capabilities: vec![],
                metadata: None,
            },
            uid,
            gid,
        )
        .unwrap();

        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["agent_count"], 1);
        // No WS connections in unit test: connected_agents reflects SyncHub.online_agents().len() = 0.
        assert_eq!(val["connected_agents"], 0);
    }

    #[tokio::test]
    async fn status_requires_auth() {
        let db = make_db();
        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
