use std::future::Future;

use axum::extract::FromRequestParts;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use agent_mesh_core::identity::UserId;

use crate::AppState;

/// Authenticated user injected by [`require_auth`] middleware.
pub struct AuthUser(pub UserId);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let result = match parts.extensions.get::<UserId>() {
            Some(id) => Ok(AuthUser(*id)),
            None => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "AuthUser extractor used without auth middleware",
            )),
        };
        std::future::ready(result)
    }
}

/// Bearer token authentication middleware.
///
/// Extracts the `Authorization: Bearer <token>` header, hashes the raw token
/// with SHA-256, and verifies it against the database.
///
/// On success, inserts the [`UserId`] into request extensions so that
/// [`AuthUser`] can be used as a handler argument.
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let raw_token = match auth_header {
        Some(value) if value.starts_with("Bearer ") => &value["Bearer ".len()..],
        Some(_) => {
            return (StatusCode::UNAUTHORIZED, "invalid authorization format").into_response()
        }
        None => return (StatusCode::UNAUTHORIZED, "missing authorization header").into_response(),
    };

    let token_hash = hash_token(raw_token);

    match state.db.verify_api_token(&token_hash) {
        Ok(Some(user_id)) => {
            request.extensions_mut().insert(user_id);
            next.run(request).await
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "invalid or expired token").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response(),
    }
}

/// Compute the SHA-256 hash of a raw API token, returning a lowercase hex string.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{middleware, Router};
    use tower::ServiceExt;

    use agent_mesh_core::user::ApiToken;

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

    fn make_test_user(state: &AppState) -> agent_mesh_core::user::User {
        use agent_mesh_core::user::User;
        let user = User {
            id: UserId::new_v4(),
            external_id: "auth-test-user".to_string(),
            provider: "test".to_string(),
            display_name: Some("Auth Test User".to_string()),
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

    fn make_expired_token(state: &AppState, user_id: UserId, raw_token: &str) {
        let token = ApiToken {
            token_hash: hash_token(raw_token),
            user_id,
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };
        state
            .db
            .create_api_token(&token)
            .expect("create expired token");
    }

    async fn test_handler(AuthUser(user_id): AuthUser) -> String {
        user_id.to_string()
    }

    fn build_app(state: AppState) -> Router {
        Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .with_state(state)
    }

    #[tokio::test]
    async fn auth_success() {
        let state = test_state();
        let user = make_test_user(&state);
        let raw_token = "valid-test-token";
        make_token(&state, user.id, raw_token);

        let app = build_app(state);
        let req = HttpRequest::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", raw_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, user.id.to_string().as_bytes());
    }

    #[tokio::test]
    async fn auth_missing_header() {
        let state = test_state();
        let app = build_app(state);
        let req = HttpRequest::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_invalid_token() {
        let state = test_state();
        let app = build_app(state);
        let req = HttpRequest::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer nonexistent-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_expired_token() {
        let state = test_state();
        let user = make_test_user(&state);
        let raw_token = "expired-test-token";
        make_expired_token(&state, user.id, raw_token);

        let app = build_app(state);
        let req = HttpRequest::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", raw_token))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_malformed_header() {
        let state = test_state();
        let app = build_app(state);
        let req = HttpRequest::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
