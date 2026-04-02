use agent_mesh_core::identity::GroupId;
use agent_mesh_core::user::{SetupKey, SetupKeyUsage};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{hash_token, AuthUser};
use crate::AppState;

/// Request body for creating a new Setup Key.
#[derive(Deserialize)]
pub struct CreateSetupKeyRequest {
    /// The group that agents registered via this key are placed in.
    pub group_id: GroupId,
    /// Usage policy: OneOff or Reusable { max_uses }.
    pub usage: SetupKeyUsage,
    /// Expiry duration in seconds from now.
    pub expires_in_secs: u64,
}

/// Response for creating a new Setup Key.
/// The `raw_key` is shown only once; the database stores the hash only.
#[derive(Serialize)]
pub struct CreateSetupKeyResponse {
    pub setup_key: SetupKey,
    /// Plaintext key — shown only at issuance.
    pub raw_key: String,
}

/// Generate a new setup key: `sk_` prefix + 32 random bytes as hex (68 chars total).
fn generate_raw_key() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sk_{hex}")
}

pub async fn create_setup_key(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateSetupKeyRequest>,
) -> Result<(StatusCode, Json<CreateSetupKeyResponse>), (StatusCode, String)> {
    let raw_key = generate_raw_key();
    let key_hash = hash_token(&raw_key);

    // Verify the caller is a member of the specified group.
    state
        .db
        .get_group_member(&req.group_id, &user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::FORBIDDEN,
            "not a member of the specified group".to_string(),
        ))?;

    let expires_secs = i64::try_from(req.expires_in_secs).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "expires_in_secs too large".to_string(),
        )
    })?;

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(expires_secs);

    let uses_remaining = match &req.usage {
        SetupKeyUsage::OneOff => None,
        SetupKeyUsage::Reusable { max_uses } => Some(*max_uses),
    };

    let key = SetupKey {
        id: Uuid::new_v4(),
        key_hash,
        user_id,
        group_id: req.group_id,
        usage: req.usage,
        uses_remaining,
        created_at: now,
        expires_at,
    };

    state
        .db
        .create_setup_key(&key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateSetupKeyResponse {
            setup_key: key,
            raw_key,
        }),
    ))
}

pub async fn list_setup_keys(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<SetupKey>>, (StatusCode, String)> {
    let keys = state
        .db
        .list_setup_keys(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(keys))
}

pub async fn revoke_setup_key(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(id_str): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let deleted = state
        .db
        .revoke_setup_key(&id, &user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "setup key not found".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request as HttpRequest, StatusCode};
    use axum::{middleware, Router};
    use tower::ServiceExt;

    use agent_mesh_core::identity::UserId;
    use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};

    use crate::auth::{hash_token, require_auth};
    use crate::db::Database;
    use crate::AppState;

    fn test_state() -> AppState {
        let db = Database::open(":memory:").expect("in-memory db");
        AppState {
            db: Arc::new(db),
            oauth_config: None,
            http_client: reqwest::Client::new(),
            sync_hub: Arc::new(crate::sync::SyncHub::new()),
        }
    }

    fn make_test_user(state: &AppState, external_id: &str) -> User {
        let user = User {
            id: UserId::new_v4(),
            external_id: external_id.to_string(),
            provider: "test".to_string(),
            display_name: None,
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

    fn make_group(state: &AppState, user: &User) -> Group {
        let group = Group {
            id: GroupId::new_v4(),
            name: "test-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        state.db.create_group(&group).expect("create test group");
        state
            .db
            .add_group_member(&GroupMember {
                group_id: group.id,
                user_id: user.id,
                role: GroupRole::Owner,
            })
            .expect("add group member");
        group
    }

    fn build_app(state: AppState) -> Router {
        let authed = Router::new()
            .route(
                "/setup-keys",
                axum::routing::post(create_setup_key).get(list_setup_keys),
            )
            .route("/setup-keys/{id}", axum::routing::delete(revoke_setup_key))
            .layer(middleware::from_fn_with_state(state.clone(), require_auth));
        authed.with_state(state)
    }

    #[tokio::test]
    async fn create_setup_key_success() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user1");
        let raw_token = "token-sk-user1";
        make_token(&state, user.id, raw_token);
        let group = make_group(&state, &user);

        let app = build_app(state);
        let body = serde_json::json!({
            "group_id": group.id,
            "usage": "OneOff",
            "expires_in_secs": 3600
        });
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/setup-keys")
            .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let raw_key = parsed["raw_key"].as_str().unwrap();
        assert!(raw_key.starts_with("sk_"), "raw_key should start with sk_");
        assert_eq!(
            parsed["setup_key"]["usage"],
            serde_json::json!("OneOff"),
            "usage should be OneOff"
        );
    }

    #[tokio::test]
    async fn create_setup_key_reusable() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user-reusable");
        let raw_token = "token-sk-user-reusable";
        make_token(&state, user.id, raw_token);
        let group = make_group(&state, &user);

        let app = build_app(state);
        let body = serde_json::json!({
            "group_id": group.id,
            "usage": {"Reusable": {"max_uses": 5}},
            "expires_in_secs": 3600
        });
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/setup-keys")
            .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["setup_key"]["uses_remaining"], 5);
    }

    #[tokio::test]
    async fn create_setup_key_forbidden_non_member_group() {
        let state = test_state();
        // owner creates a group; caller is a different user not in that group
        let owner = make_test_user(&state, "sk-owner-forbidden");
        let group = make_group(&state, &owner);

        let caller = make_test_user(&state, "sk-caller-forbidden");
        let caller_token = "token-sk-caller-forbidden";
        make_token(&state, caller.id, caller_token);

        let app = build_app(state);
        let body = serde_json::json!({
            "group_id": group.id,
            "usage": "OneOff",
            "expires_in_secs": 3600
        });
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/setup-keys")
            .header(header::AUTHORIZATION, format!("Bearer {caller_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_setup_key_without_auth() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user-noauth");
        let group = make_group(&state, &user);

        let app = build_app(state);
        let body = serde_json::json!({
            "group_id": group.id,
            "usage": "OneOff",
            "expires_in_secs": 3600
        });
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/setup-keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_setup_keys_success() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user-list");
        let raw_token = "token-sk-user-list";
        make_token(&state, user.id, raw_token);
        let group = make_group(&state, &user);

        // create two keys via DB directly
        for i in 0..2u32 {
            let key = SetupKey {
                id: Uuid::new_v4(),
                key_hash: hash_token(&format!("raw-key-{i}")),
                user_id: user.id,
                group_id: group.id,
                usage: SetupKeyUsage::OneOff,
                uses_remaining: None,
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };
            state.db.create_setup_key(&key).expect("create key");
        }

        let app = build_app(state);
        let req = HttpRequest::builder()
            .method("GET")
            .uri("/setup-keys")
            .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let keys: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn list_setup_keys_without_auth() {
        let state = test_state();
        let app = build_app(state);
        let req = HttpRequest::builder()
            .method("GET")
            .uri("/setup-keys")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_setup_key_success() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user-revoke");
        let raw_token = "token-sk-user-revoke";
        make_token(&state, user.id, raw_token);
        let group = make_group(&state, &user);

        let key = SetupKey {
            id: Uuid::new_v4(),
            key_hash: hash_token("raw-revoke-key"),
            user_id: user.id,
            group_id: group.id,
            usage: SetupKeyUsage::OneOff,
            uses_remaining: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let key_id = key.id;
        state.db.create_setup_key(&key).expect("create key");

        let app = build_app(state);
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/setup-keys/{key_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revoke_setup_key_not_found() {
        let state = test_state();
        let user = make_test_user(&state, "sk-user-revoke-nf");
        let raw_token = "token-sk-user-revoke-nf";
        make_token(&state, user.id, raw_token);

        let app = build_app(state);
        let nonexistent_id = Uuid::new_v4();
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/setup-keys/{nonexistent_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_setup_key_wrong_owner() {
        let state = test_state();
        let owner = make_test_user(&state, "sk-owner-wrong");
        let owner_token = "token-sk-owner-wrong";
        make_token(&state, owner.id, owner_token);
        let group = make_group(&state, &owner);

        let other_user = make_test_user(&state, "sk-other-wrong");
        let other_token = "token-sk-other-wrong";
        make_token(&state, other_user.id, other_token);

        let key = SetupKey {
            id: Uuid::new_v4(),
            key_hash: hash_token("raw-wrong-owner-key"),
            user_id: owner.id,
            group_id: group.id,
            usage: SetupKeyUsage::OneOff,
            uses_remaining: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let key_id = key.id;
        state.db.create_setup_key(&key).expect("create key");

        // other_user tries to revoke owner's key
        let app = build_app(state);
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/setup-keys/{key_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
