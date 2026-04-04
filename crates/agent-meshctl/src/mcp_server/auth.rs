use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

type AuthFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>;

async fn do_auth(
    token: Option<Arc<String>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected) = token.as_deref() {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        match auth_header {
            Some(t) if t == expected => {}
            _ => return Err(StatusCode::UNAUTHORIZED),
        }
    }
    Ok(next.run(req).await)
}

/// Returns an axum middleware layer that validates Bearer tokens.
///
/// When `token` is `None`, all requests are passed through (development mode).
/// When `token` is `Some(expected)`, requests must include
/// `Authorization: Bearer <expected>`; otherwise `401 Unauthorized` is returned.
pub fn bearer_auth_layer(
    token: Option<String>,
) -> axum::middleware::FromFnLayer<
    impl Fn(Request, Next) -> AuthFuture + Clone + Send + Sync + 'static,
    (),
    (Request,),
> {
    let token = token.map(Arc::new);
    axum::middleware::from_fn(move |req: Request, next: Next| {
        let t = token.clone();
        Box::pin(do_auth(t, req, next)) as AuthFuture
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tower::util::ServiceExt;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn build_app(token: Option<String>) -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(bearer_auth_layer(token))
    }

    #[tokio::test]
    async fn token_match_passes() {
        let app = build_app(Some("secret".to_string()));
        let req = Request::builder()
            .uri("/test")
            .header(AUTHORIZATION, "Bearer secret")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_mismatch_returns_401() {
        let app = build_app(Some("secret".to_string()));
        let req = Request::builder()
            .uri("/test")
            .header(AUTHORIZATION, "Bearer wrong")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let app = build_app(Some("secret".to_string()));
        let req = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_token_passes_all_requests() {
        let app = build_app(None);
        let req = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
