use std::collections::HashSet;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use agent_mesh_core::agent_card::AgentCardQuery;
use agent_mesh_core::identity::GroupId;
use agent_mesh_core::message::KeyRevocation;
use agent_mesh_core::sync::SyncEvent;

use crate::auth::AuthUser;
use crate::db::RevocationRow;
use crate::AppState;

/// API response for a single revocation record.
#[derive(Serialize)]
pub struct RevocationResponse {
    pub agent_id: String,
    pub reason: Option<String>,
    pub revoked_by: String,
    pub timestamp: i64,
    pub created_at: String,
}

impl From<RevocationRow> for RevocationResponse {
    fn from(row: RevocationRow) -> Self {
        Self {
            agent_id: row.agent_id,
            reason: row.reason,
            revoked_by: row.revoked_by.0.to_string(),
            timestamp: row.timestamp,
            created_at: row.created_at,
        }
    }
}

/// `POST /revocations` — submit a signed key revocation.
///
/// The signature is verified before storing. Returns 400 if verification fails.
pub async fn revoke_key(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(rev): Json<KeyRevocation>,
) -> Result<(StatusCode, Json<RevocationResponse>), (StatusCode, String)> {
    // Verify the revocation signature before persisting.
    rev.verify().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid revocation signature: {e}"),
        )
    })?;

    let row = RevocationRow {
        agent_id: rev.agent_id.as_str().to_string(),
        reason: rev.reason.clone(),
        revoked_by: user_id,
        signature: rev.signature.clone(),
        timestamp: rev.timestamp,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    state
        .db
        .create_revocation(&row)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Broadcast KeyRevoked to all groups that contain this agent.
    // If the agent is not found in agent_cards (e.g. already deleted), skip broadcast.
    let query = AgentCardQuery {
        agent_id: Some(rev.agent_id.clone()),
        ..Default::default()
    };
    if let Ok(cards) = state.db.search(&query) {
        let group_ids: HashSet<GroupId> = cards.iter().map(|c| c.group_id).collect();
        for gid in group_ids {
            state
                .sync_hub
                .broadcast_to_group(&gid, &SyncEvent::KeyRevoked(rev.clone()))
                .await;
        }
    }

    Ok((StatusCode::CREATED, Json(RevocationResponse::from(row))))
}

/// `GET /revocations` — list all revocation records.
pub async fn list_revocations(
    State(state): State<AppState>,
    AuthUser(_user_id): AuthUser,
) -> Result<Json<Vec<RevocationResponse>>, (StatusCode, String)> {
    let rows = state
        .db
        .list_revocations()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let revs: Vec<RevocationResponse> = rows.into_iter().map(RevocationResponse::from).collect();
    Ok(Json(revs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hash_token;
    use crate::{app, AppState};
    use agent_mesh_core::identity::{AgentKeypair, UserId};
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
    ) -> (UserId, String) {
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

        (user.id, raw_token)
    }

    #[tokio::test]
    async fn revoke_key_valid_signature_returns_201() {
        let db = make_db();
        let (_uid, token) = setup_user_group_token(&db, "rev-u1");
        let app = app(make_app_state(db));

        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, Some("test reason".to_string()));

        let req = Request::builder()
            .method("POST")
            .uri("/revocations")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&rev).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["agent_id"], rev.agent_id.as_str());
        assert_eq!(val["reason"], "test reason");
    }

    #[tokio::test]
    async fn revoke_key_invalid_signature_returns_400() {
        let db = make_db();
        let (_uid, token) = setup_user_group_token(&db, "rev-bad-u1");
        let app = app(make_app_state(db));

        let kp = AgentKeypair::generate();
        let mut rev = KeyRevocation::new(&kp, None);
        // Tamper with the timestamp to invalidate the signature.
        rev.timestamp += 1;

        let req = Request::builder()
            .method("POST")
            .uri("/revocations")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&rev).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_revocations_returns_all() {
        let db = make_db();
        let (uid, token) = setup_user_group_token(&db, "rev-list-u1");

        // Insert two revocations directly.
        db.create_revocation(&RevocationRow {
            agent_id: "agent-rev-a".to_string(),
            reason: None,
            revoked_by: uid,
            signature: "sig".to_string(),
            timestamp: 1000,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .unwrap();
        db.create_revocation(&RevocationRow {
            agent_id: "agent-rev-b".to_string(),
            reason: Some("reason-b".to_string()),
            revoked_by: uid,
            signature: "sig2".to_string(),
            timestamp: 2000,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .unwrap();

        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/revocations")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let revs: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(revs.len(), 2);
    }

    #[tokio::test]
    async fn revocations_requires_auth() {
        let db = make_db();
        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/revocations")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
