use agent_mesh_core::identity::{GroupId, UserId};
use agent_mesh_core::user::{Group, GroupMember, GroupRole};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_id: UserId,
    pub role: GroupRole,
}

pub async fn create_group(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<Group>), (StatusCode, String)> {
    let group = Group {
        id: GroupId::new_v4(),
        name: req.name,
        created_by: user_id,
        created_at: chrono::Utc::now(),
    };
    state
        .db
        .create_group(&group)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let member = GroupMember {
        group_id: group.id,
        user_id,
        role: GroupRole::Owner,
    };
    state
        .db
        .add_group_member(&member)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((StatusCode::CREATED, Json(group)))
}

pub async fn list_groups(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Group>>, (StatusCode, String)> {
    let groups = state
        .db
        .list_groups_for_user(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(groups))
}

pub async fn add_member(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path(group_id_str): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let group_id =
        GroupId::parse_str(&group_id_str).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let caller_membership = state
        .db
        .get_group_member(&group_id, &caller_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match caller_membership {
        Some(m) if m.role == GroupRole::Owner || m.role == GroupRole::Admin => {}
        _ => return Err((StatusCode::FORBIDDEN, "insufficient permissions".into())),
    }

    let member = GroupMember {
        group_id,
        user_id: req.user_id,
        role: req.role,
    };
    state
        .db
        .add_group_member(&member)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn remove_member(
    State(state): State<AppState>,
    AuthUser(caller_id): AuthUser,
    Path((group_id_str, target_user_id_str)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let group_id =
        GroupId::parse_str(&group_id_str).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let target_user_id = UserId::parse_str(&target_user_id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let caller_membership = state
        .db
        .get_group_member(&group_id, &caller_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match caller_membership {
        Some(m) if m.role == GroupRole::Owner || m.role == GroupRole::Admin => {}
        _ => return Err((StatusCode::FORBIDDEN, "insufficient permissions".into())),
    }

    let target_membership = state
        .db
        .get_group_member(&group_id, &target_user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(m) = target_membership {
        if m.role == GroupRole::Owner {
            return Err((
                StatusCode::BAD_REQUEST,
                "cannot remove the group owner".into(),
            ));
        }
    }

    state
        .db
        .remove_group_member(&group_id, &target_user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request as HttpRequest, StatusCode};
    use axum::{middleware, Router};
    use tower::ServiceExt;

    use agent_mesh_core::user::{ApiToken, User};

    use crate::auth::{hash_token, require_auth};
    use crate::db::Database;
    use crate::AppState;

    fn test_state() -> AppState {
        let db = Database::open(":memory:").expect("in-memory db");
        AppState {
            db: Arc::new(db),
            oauth_config: None,
            http_client: reqwest::Client::new(),
        }
    }

    fn make_test_user(state: &AppState, external_id: &str) -> User {
        let user = User {
            id: UserId::new_v4(),
            external_id: external_id.to_string(),
            provider: "test".to_string(),
            display_name: Some(external_id.to_string()),
            created_at: chrono::Utc::now(),
        };
        state.db.create_user(&user).expect("create test user");
        user
    }

    fn make_token(state: &AppState, user_id: UserId, raw_token: &str) {
        let token = ApiToken {
            token_hash: hash_token(raw_token),
            user_id,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        state
            .db
            .create_api_token(&token)
            .expect("create test token");
    }

    fn build_app(state: AppState) -> Router {
        let authed = Router::new()
            .route("/groups", axum::routing::post(create_group))
            .route("/groups", axum::routing::get(list_groups))
            .route("/groups/{id}/members", axum::routing::post(add_member))
            .route(
                "/groups/{id}/members/{user_id}",
                axum::routing::delete(remove_member),
            )
            .layer(middleware::from_fn_with_state(state.clone(), require_auth));
        authed.with_state(state)
    }

    fn create_group_body(name: &str) -> Body {
        Body::from(format!(r#"{{"name":"{}"}}"#, name))
    }

    // Helper: POSTでGroupを作成し、Group JSONを返す
    async fn setup_group(state: &AppState, owner_token: &str, name: &str) -> Group {
        let app = build_app(state.clone());
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/groups")
            .header(header::AUTHORIZATION, format!("Bearer {}", owner_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(create_group_body(name))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).expect("valid group json")
    }

    #[tokio::test]
    async fn create_group_success() {
        let state = test_state();
        let user = make_test_user(&state, "user1");
        let raw_token = "token-user1";
        make_token(&state, user.id.clone(), raw_token);

        let app = build_app(state.clone());
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/groups")
            .header(header::AUTHORIZATION, format!("Bearer {}", raw_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(create_group_body("my-group"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let group: Group = serde_json::from_slice(&bytes).expect("valid group json");
        assert_eq!(group.name, "my-group");
        assert_eq!(group.created_by, user.id);

        // Owner として追加されていることを確認
        let member = state
            .db
            .get_group_member(&group.id, &user.id)
            .expect("get member")
            .expect("member should exist");
        assert_eq!(member.role, GroupRole::Owner);
    }

    #[tokio::test]
    async fn list_groups_returns_own_groups() {
        let state = test_state();
        let user = make_test_user(&state, "user2");
        let raw_token = "token-user2";
        make_token(&state, user.id.clone(), raw_token);

        let group = setup_group(&state, raw_token, "list-test-group").await;

        let app = build_app(state.clone());
        let req = HttpRequest::builder()
            .method("GET")
            .uri("/groups")
            .header(header::AUTHORIZATION, format!("Bearer {}", raw_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: Vec<Group> = serde_json::from_slice(&bytes).expect("valid groups json");
        assert!(groups.iter().any(|g| g.id == group.id));
    }

    #[tokio::test]
    async fn add_member_by_owner() {
        let state = test_state();
        let owner = make_test_user(&state, "owner3");
        let owner_token = "token-owner3";
        make_token(&state, owner.id.clone(), owner_token);

        let new_member = make_test_user(&state, "member3");

        let group = setup_group(&state, owner_token, "owner-add-group").await;

        let app = build_app(state.clone());
        let body = format!(r#"{{"user_id":"{}","role":"Member"}}"#, new_member.id);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/groups/{}/members", group.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", owner_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn add_member_by_admin() {
        let state = test_state();
        let owner = make_test_user(&state, "owner4");
        let owner_token = "token-owner4";
        make_token(&state, owner.id.clone(), owner_token);

        let admin = make_test_user(&state, "admin4");
        let admin_token = "token-admin4";
        make_token(&state, admin.id.clone(), admin_token);

        let new_member = make_test_user(&state, "member4");

        let group = setup_group(&state, owner_token, "admin-add-group").await;

        // admin を Admin として追加
        state
            .db
            .add_group_member(&GroupMember {
                group_id: group.id.clone(),
                user_id: admin.id.clone(),
                role: GroupRole::Admin,
            })
            .expect("add admin");

        let app = build_app(state.clone());
        let body = format!(r#"{{"user_id":"{}","role":"Member"}}"#, new_member.id);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/groups/{}/members", group.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", admin_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn add_member_by_member_forbidden() {
        let state = test_state();
        let owner = make_test_user(&state, "owner5");
        let owner_token = "token-owner5";
        make_token(&state, owner.id.clone(), owner_token);

        let plain_member = make_test_user(&state, "plain5");
        let plain_token = "token-plain5";
        make_token(&state, plain_member.id.clone(), plain_token);

        let another = make_test_user(&state, "another5");

        let group = setup_group(&state, owner_token, "member-forbidden-group").await;

        // plain_member を Member として追加
        state
            .db
            .add_group_member(&GroupMember {
                group_id: group.id.clone(),
                user_id: plain_member.id.clone(),
                role: GroupRole::Member,
            })
            .expect("add plain member");

        let app = build_app(state.clone());
        let body = format!(r#"{{"user_id":"{}","role":"Member"}}"#, another.id);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/groups/{}/members", group.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", plain_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn add_member_not_in_group_forbidden() {
        let state = test_state();
        let owner = make_test_user(&state, "owner6");
        let owner_token = "token-owner6";
        make_token(&state, owner.id.clone(), owner_token);

        let outsider = make_test_user(&state, "outsider6");
        let outsider_token = "token-outsider6";
        make_token(&state, outsider.id.clone(), outsider_token);

        let target = make_test_user(&state, "target6");

        let group = setup_group(&state, owner_token, "outsider-forbidden-group").await;

        let app = build_app(state.clone());
        let body = format!(r#"{{"user_id":"{}","role":"Member"}}"#, target.id);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/groups/{}/members", group.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", outsider_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn remove_member_by_owner() {
        let state = test_state();
        let owner = make_test_user(&state, "owner7");
        let owner_token = "token-owner7";
        make_token(&state, owner.id.clone(), owner_token);

        let member = make_test_user(&state, "member7");

        let group = setup_group(&state, owner_token, "remove-test-group").await;

        state
            .db
            .add_group_member(&GroupMember {
                group_id: group.id.clone(),
                user_id: member.id.clone(),
                role: GroupRole::Member,
            })
            .expect("add member");

        let app = build_app(state.clone());
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/groups/{}/members/{}", group.id, member.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", owner_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn remove_owner_forbidden() {
        let state = test_state();
        let owner = make_test_user(&state, "owner8");
        let owner_token = "token-owner8";
        make_token(&state, owner.id.clone(), owner_token);

        let group = setup_group(&state, owner_token, "remove-owner-group").await;

        let app = build_app(state.clone());
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/groups/{}/members/{}", group.id, owner.id))
            .header(header::AUTHORIZATION, format!("Bearer {}", owner_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
