use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::MeshCredentials;
use crate::node::NodeState;

// ── Shared state ──────────────────────────────────────────────────────────────

/// State shared across all Local API handlers.
#[derive(Clone)]
pub struct LocalApiState {
    /// Control Plane URL (may be set dynamically via POST /login).
    pub cp_url: Arc<RwLock<Option<String>>>,
    /// Bearer token for CP authentication.
    pub bearer_token: Arc<RwLock<Option<String>>>,
    /// Current daemon state.
    pub node_state: Arc<RwLock<NodeState>>,
    /// HTTP client for CP proxy requests.
    pub http_client: reqwest::Client,
    /// Directory for credential storage (`~/.mesh/`).
    pub mesh_dir: PathBuf,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: LocalApiState) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/login", post(login_start))
        .route("/login/poll", post(login_poll))
        .route("/agents", post(proxy_agents_create))
        .route("/agents", get(proxy_agents_list))
        .route("/groups", post(proxy_groups_create))
        .route("/groups", get(proxy_groups_list))
        .route("/groups/{id}/members", post(proxy_groups_add_member))
        .route(
            "/groups/{id}/members/{user_id}",
            delete(proxy_groups_remove_member),
        )
        .route("/revocations", post(proxy_revocations_create))
        .with_state(state)
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct StatusResponse {
    state: NodeState,
    cp_url: Option<String>,
    has_token: bool,
}

#[derive(Debug, Deserialize)]
struct LoginStartRequest {
    cp_url: String,
}

#[derive(Debug, Deserialize)]
struct LoginPollRequest {
    device_code: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn status(State(state): State<LocalApiState>) -> Json<StatusResponse> {
    let node_state = state.node_state.read().await.clone();
    let cp_url = state.cp_url.read().await.clone();
    let has_token = state.bearer_token.read().await.is_some();
    Json(StatusResponse {
        state: node_state,
        cp_url,
        has_token,
    })
}

async fn login_start(
    State(state): State<LocalApiState>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Store cp_url in shared state.
    {
        let mut lock = state.cp_url.write().await;
        *lock = Some(req.cp_url.clone());
    }

    // POST /oauth/device to CP.
    let url = format!("{}/oauth/device", req.cp_url.trim_end_matches('/'));
    let resp = state
        .http_client
        .post(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // On success, also persist cp_url to credentials file.
    if resp.status().is_success() {
        let existing_token = state.bearer_token.read().await.clone();
        let creds = MeshCredentials {
            bearer_token: existing_token,
            cp_url: Some(req.cp_url.clone()),
        };
        creds
            .save(&state.mesh_dir)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    convert_response(resp).await
}

async fn login_poll(
    State(state): State<LocalApiState>,
    Json(req): Json<LoginPollRequest>,
) -> Result<Response, (StatusCode, String)> {
    let cp_url = state.cp_url.read().await.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "cp_url not configured".into(),
        )
    })?;

    let url = format!("{}/oauth/token", cp_url.trim_end_matches('/'));
    let body = serde_json::json!({ "device_code": req.device_code });

    let resp = state
        .http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // On success (api_token present), persist token and transition state.
    if status.is_success() {
        if let Some(token) = resp_body.get("api_token").and_then(|v| v.as_str()) {
            let token = token.to_string();

            *state.bearer_token.write().await = Some(token.clone());
            *state.node_state.write().await = NodeState::Authenticated;

            let cp_url_stored = state.cp_url.read().await.clone();
            let creds = MeshCredentials {
                bearer_token: Some(token),
                cp_url: cp_url_stored,
            };
            creds
                .save(&state.mesh_dir)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    // Return the CP response body as-is.
    let axum_status =
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    Response::builder()
        .status(axum_status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&resp_body)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        ))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ── Proxy handlers (thin wrappers around proxy_to_cp) ────────────────────────

async fn proxy_agents_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(&state, reqwest::Method::POST, "/agents", Some(body)).await
}

async fn proxy_agents_list(
    State(state): State<LocalApiState>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(&state, reqwest::Method::GET, "/agents", None).await
}

async fn proxy_groups_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(&state, reqwest::Method::POST, "/groups", Some(body)).await
}

async fn proxy_groups_list(
    State(state): State<LocalApiState>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(&state, reqwest::Method::GET, "/groups", None).await
}

async fn proxy_groups_add_member(
    State(state): State<LocalApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(
        &state,
        reqwest::Method::POST,
        &format!("/groups/{id}/members"),
        Some(body),
    )
    .await
}

async fn proxy_groups_remove_member(
    State(state): State<LocalApiState>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(
        &state,
        reqwest::Method::DELETE,
        &format!("/groups/{id}/members/{user_id}"),
        None,
    )
    .await
}

async fn proxy_revocations_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, (StatusCode, String)> {
    proxy_to_cp(&state, reqwest::Method::POST, "/revocations", Some(body)).await
}

// ── Core proxy function ───────────────────────────────────────────────────────

/// Forward a request to the Control Plane, injecting the stored Bearer token.
///
/// Returns an axum `Response` that mirrors the CP response (status + body).
async fn proxy_to_cp(
    state: &LocalApiState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Response, (StatusCode, String)> {
    let cp_url = state.cp_url.read().await.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "cp_url not configured".into(),
        )
    })?;

    let token = state
        .bearer_token
        .read()
        .await
        .clone()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "not authenticated".into()))?;

    let url = format!("{}{}", cp_url.trim_end_matches('/'), path);
    let mut req = state.http_client.request(method, &url).bearer_auth(&token);

    if let Some(b) = body {
        req = req.json(&b);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    convert_response(resp).await
}

/// Convert a `reqwest::Response` into an `axum::response::Response`.
async fn convert_response(resp: reqwest::Response) -> Result<Response, (StatusCode, String)> {
    let status = resp.status();
    let axum_status =
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    // Copy content-type header if present.
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let mut builder = Response::builder().status(axum_status);
    if let Some(ct) = content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
    }

    builder
        .body(axum::body::Body::from(bytes))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;

    // ── Helpers ────────────────────────────────────────────────────────────────

    fn temp_mesh_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("meshd-local-api-test-{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_state(cp_url: Option<String>, token: Option<String>, dir: PathBuf) -> LocalApiState {
        LocalApiState {
            cp_url: Arc::new(RwLock::new(cp_url)),
            bearer_token: Arc::new(RwLock::new(token)),
            node_state: Arc::new(RwLock::new(NodeState::Started)),
            http_client: reqwest::Client::new(),
            mesh_dir: dir,
        }
    }

    /// Start a mock TCP HTTP server and return its base URL.
    async fn mock_cp_server(handler: axum::routing::MethodRouter, path: &str) -> String {
        let app = axum::Router::new().route(path, handler);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        format!("http://127.0.0.1:{}", addr.port())
    }

    // ── Unit test: convert_response ────────────────────────────────────────────

    #[tokio::test]
    async fn convert_response_preserves_status_and_body() {
        // Create a tiny HTTP server that returns 201 + JSON body.
        let app = axum::Router::new().route(
            "/echo",
            get(|| async { (StatusCode::CREATED, Json(serde_json::json!({"ok": true}))) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/echo", addr.port()))
            .send()
            .await
            .unwrap();

        let axum_resp = convert_response(resp).await.unwrap();
        assert_eq!(axum_resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(axum_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
    }

    // ── Status endpoint ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_started_no_token() {
        let dir = temp_mesh_dir("status-started");
        let state = make_state(None, None, dir.clone());
        let app = router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/status")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], "Started");
        assert_eq!(json["has_token"], false);
        assert!(json["cp_url"].is_null());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn status_authenticated_with_token() {
        let dir = temp_mesh_dir("status-auth");
        let state = LocalApiState {
            cp_url: Arc::new(RwLock::new(Some("http://cp.test".into()))),
            bearer_token: Arc::new(RwLock::new(Some("tok-xyz".into()))),
            node_state: Arc::new(RwLock::new(NodeState::Authenticated)),
            http_client: reqwest::Client::new(),
            mesh_dir: dir.clone(),
        };
        let app = router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/status")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], "Authenticated");
        assert_eq!(json["has_token"], true);
        assert_eq!(json["cp_url"], "http://cp.test");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── Unauthenticated proxy rejection ───────────────────────────────────────

    #[tokio::test]
    async fn proxy_returns_401_without_token() {
        let dir = temp_mesh_dir("proxy-401");
        let state = make_state(Some("http://cp.test".into()), None, dir.clone());
        let app = router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/agents")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn proxy_returns_503_without_cp_url() {
        let dir = temp_mesh_dir("proxy-503");
        let state = make_state(None, Some("tok-abc".into()), dir.clone());
        let app = router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/agents")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── CP proxy forwarding ────────────────────────────────────────────────────

    #[tokio::test]
    async fn proxy_agents_list_forwards_bearer_to_cp() {
        let dir = temp_mesh_dir("proxy-agents");
        // Verify Authorization header is forwarded correctly using axum's HeaderMap extractor.
        let cp_base = mock_cp_server(
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                let auth = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert_eq!(auth, "Bearer tok-test");
                Json(serde_json::json!([{"id": "a1"}]))
            }),
            "/agents",
        )
        .await;

        let state = make_state(Some(cp_base), Some("tok-test".into()), dir.clone());
        let app = router(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/agents")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["id"], "a1");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── Login flow ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_start_calls_oauth_device_and_returns_response() {
        let dir = temp_mesh_dir("login-start");
        // Mock CP: POST /oauth/device
        let cp_base = mock_cp_server(
            axum::routing::post(|| async {
                Json(serde_json::json!({
                    "device_code": "dev-code-123",
                    "user_code": "ABCD-1234",
                    "verification_uri": "https://cp.test/activate",
                    "expires_in": 300,
                    "interval": 5,
                }))
            }),
            "/oauth/device",
        )
        .await;

        let state = make_state(None, None, dir.clone());
        let app = router(state);

        let body = serde_json::to_vec(&serde_json::json!({ "cp_url": cp_base })).unwrap();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/login")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["user_code"], "ABCD-1234");
        assert_eq!(json["device_code"], "dev-code-123");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn login_poll_success_saves_token_and_transitions_state() {
        let dir = temp_mesh_dir("login-poll-ok");

        // Mock CP: POST /oauth/token → returns api_token
        let cp_base = mock_cp_server(
            axum::routing::post(|| async {
                Json(serde_json::json!({ "api_token": "tok-from-cp" }))
            }),
            "/oauth/token",
        )
        .await;

        let node_state = Arc::new(RwLock::new(NodeState::Started));
        let bearer_token: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
        let state = LocalApiState {
            cp_url: Arc::new(RwLock::new(Some(cp_base))),
            bearer_token: Arc::clone(&bearer_token),
            node_state: Arc::clone(&node_state),
            http_client: reqwest::Client::new(),
            mesh_dir: dir.clone(),
        };
        let app = router(state);

        let body =
            serde_json::to_vec(&serde_json::json!({ "device_code": "dev-code-abc" })).unwrap();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/login/poll")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // State must have transitioned to Authenticated.
        assert_eq!(*node_state.read().await, NodeState::Authenticated);
        assert_eq!(bearer_token.read().await.as_deref(), Some("tok-from-cp"));

        // config.toml must have been saved.
        let creds = MeshCredentials::load(&dir).unwrap();
        assert_eq!(creds.bearer_token.as_deref(), Some("tok-from-cp"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn login_poll_pending_does_not_save_token() {
        let dir = temp_mesh_dir("login-poll-pending");

        // Mock CP: POST /oauth/token → authorization_pending
        let cp_base = mock_cp_server(
            axum::routing::post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "authorization_pending" })),
                )
            }),
            "/oauth/token",
        )
        .await;

        let node_state = Arc::new(RwLock::new(NodeState::Started));
        let state = LocalApiState {
            cp_url: Arc::new(RwLock::new(Some(cp_base))),
            bearer_token: Arc::new(RwLock::new(None)),
            node_state: Arc::clone(&node_state),
            http_client: reqwest::Client::new(),
            mesh_dir: dir.clone(),
        };
        let app = router(state);

        let body =
            serde_json::to_vec(&serde_json::json!({ "device_code": "dev-code-xyz" })).unwrap();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/login/poll")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        // CP returned 400, so we forward that status.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // State must remain Started.
        assert_eq!(*node_state.read().await, NodeState::Started);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ── UDS bind test ──────────────────────────────────────────────────────────

    /// Verifies that axum can serve requests over a Unix domain socket.
    /// Uses a short path to stay within the 108-byte OS limit.
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_server_responds_to_status_request() {
        use hyper::client::conn::http1;
        use hyper::Request;
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;

        // Create temp dir with a short absolute path.
        let dir = std::env::temp_dir().join("mla");
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("s.sock");
        let _ = std::fs::remove_file(&sock_path);

        let state = make_state(None, None, dir.clone());
        let app = router(state).into_make_service();

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let meta = std::fs::metadata(&sock_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "expected 0700 but got {mode:o}");
        }

        tokio::spawn(axum::serve(listener, app).into_future());

        // Connect via UDS and send HTTP/1.1 GET /status.
        let stream = UnixStream::connect(&sock_path).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .header("host", "localhost")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["state"], "Started");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
