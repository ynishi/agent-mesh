use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::db::AclRuleRow;
use crate::AppState;

/// Request body for creating an ACL rule.
#[derive(Deserialize)]
pub struct CreateAclRuleRequest {
    /// Source agent ID (string form).
    pub source: String,
    /// Target agent ID (string form).
    pub target: String,
    /// Capabilities the source may invoke on the target.
    pub allowed_capabilities: Vec<String>,
}

/// API response for a single ACL rule.
#[derive(Serialize)]
pub struct AclRuleResponse {
    pub id: String,
    pub group_id: String,
    pub source: String,
    pub target: String,
    pub allowed_capabilities: Vec<String>,
    pub created_at: String,
}

impl TryFrom<AclRuleRow> for AclRuleResponse {
    type Error = anyhow::Error;

    fn try_from(row: AclRuleRow) -> Result<Self, Self::Error> {
        let caps: Vec<String> = serde_json::from_str(&row.allowed_capabilities)?;
        Ok(Self {
            id: row.id,
            group_id: row.group_id.0.to_string(),
            source: row.source,
            target: row.target,
            allowed_capabilities: caps,
            created_at: row.created_at,
        })
    }
}

/// `POST /acl` — create an ACL rule scoped to the authenticated user's group.
///
/// TODO: broadcast after SyncHub is available (Subtask 2).
pub async fn create_rule(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateAclRuleRequest>,
) -> Result<(StatusCode, Json<AclRuleResponse>), (StatusCode, String)> {
    let group_id = state
        .db
        .ensure_user_has_group(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let caps_json = serde_json::to_string(&req.allowed_capabilities)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = AclRuleRow {
        id: uuid::Uuid::new_v4().to_string(),
        group_id,
        source: req.source,
        target: req.target,
        allowed_capabilities: caps_json,
        created_by: user_id,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    state
        .db
        .create_acl_rule(&row)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = AclRuleResponse::try_from(row)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((StatusCode::CREATED, Json(resp)))
}

/// `GET /acl` — list ACL rules scoped to the authenticated user's group.
pub async fn list_rules(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<AclRuleResponse>>, (StatusCode, String)> {
    let group_id = state
        .db
        .ensure_user_has_group(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = state
        .db
        .list_acl_rules_for_group(&group_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rules: Result<Vec<AclRuleResponse>, _> =
        rows.into_iter().map(AclRuleResponse::try_from).collect();
    let rules = rules.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(rules))
}

/// `DELETE /acl/{id}` — delete an ACL rule, only if it belongs to the user's group.
///
/// Returns 204 on success, 404 if not found or not in the user's group.
pub async fn delete_rule(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let group_id = state
        .db
        .ensure_user_has_group(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let deleted = state
        .db
        .delete_acl_rule(&id, &group_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "acl rule not found".into()))
    }
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
    async fn create_rule_returns_201() {
        let db = make_db();
        let (_uid, _gid, token) = setup_user_group_token(&db, "acl-u1");
        let app = app(make_app_state(db));

        let body = serde_json::json!({
            "source": "agent-a",
            "target": "agent-b",
            "allowed_capabilities": ["scheduling"]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/acl")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["source"], "agent-a");
        assert_eq!(val["target"], "agent-b");
        assert_eq!(val["allowed_capabilities"][0], "scheduling");
    }

    #[tokio::test]
    async fn list_rules_returns_own_group_only() {
        let db = make_db();
        let (_uid1, gid1, token1) = setup_user_group_token(&db, "acl-list-u1");
        let (_uid2, _gid2, _token2) = setup_user_group_token(&db, "acl-list-u2");

        // Insert a rule for user1's group directly via DB.
        db.create_acl_rule(&AclRuleRow {
            id: uuid::Uuid::new_v4().to_string(),
            group_id: gid1,
            source: "src-1".to_string(),
            target: "dst-1".to_string(),
            allowed_capabilities: r#"["cap1"]"#.to_string(),
            created_by: _uid1,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .unwrap();

        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/acl")
            .header("authorization", format!("Bearer {token1}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["source"], "src-1");
    }

    #[tokio::test]
    async fn delete_rule_returns_204() {
        let db = make_db();
        let (_uid, gid, token) = setup_user_group_token(&db, "acl-del-u1");

        let rule_id = uuid::Uuid::new_v4().to_string();
        db.create_acl_rule(&AclRuleRow {
            id: rule_id.clone(),
            group_id: gid,
            source: "s".to_string(),
            target: "t".to_string(),
            allowed_capabilities: r#"[]"#.to_string(),
            created_by: _uid,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .unwrap();

        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/acl/{rule_id}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_rule_not_found_returns_404() {
        let db = make_db();
        let (_uid, _gid, token) = setup_user_group_token(&db, "acl-del-nf-u1");
        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("DELETE")
            .uri("/acl/nonexistent-id")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn acl_requires_auth() {
        let db = make_db();
        let app = app(make_app_state(db));

        let req = Request::builder()
            .method("GET")
            .uri("/acl")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
