use super::*;
use std::collections::HashMap;
use std::future::IntoFuture;

use agent_mesh_core::noise::NoiseKeypair;
use tokio::sync::Mutex;

use crate::node::{SharedPending, SharedSessions, SharedSink};

// ── Helpers ────────────────────────────────────────────────────────────────

fn temp_mesh_dir(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("meshd-local-api-test-{suffix}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_shared_sink() -> SharedSink {
    Arc::new(Mutex::new(None))
}

fn make_shared_sessions() -> SharedSessions {
    Arc::new(Mutex::new(HashMap::new()))
}

fn make_shared_pending() -> SharedPending {
    Arc::new(Mutex::new(HashMap::new()))
}

fn make_noise_keypair() -> Arc<NoiseKeypair> {
    Arc::new(NoiseKeypair::generate().expect("noise keygen"))
}

fn make_state(cp_url: Option<String>, token: Option<String>, dir: PathBuf) -> LocalApiState {
    LocalApiState {
        cp_url: Arc::new(RwLock::new(cp_url)),
        bearer_token: Arc::new(RwLock::new(token)),
        node_state: Arc::new(RwLock::new(NodeState::Started)),
        http_client: reqwest::Client::new(),
        mesh_dir: dir,
        peers: Arc::new(RwLock::new(Vec::new())),
        revoked_keys: Arc::new(RwLock::new(std::collections::HashSet::new())),
        keypair: Arc::new(RwLock::new(AgentKeypair::generate())),
        pending_keypair: Arc::new(RwLock::new(None)),
        relay_cancel: Arc::new(Notify::new()),
        config_path: None,
        shared_sink: make_shared_sink(),
        shared_sessions: make_shared_sessions(),
        shared_pending: make_shared_pending(),
        noise_keypair: make_noise_keypair(),
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
    assert_eq!(json["peers_count"], 0);
    assert_eq!(json["revoked_count"], 0);
    assert_eq!(json["online_peers"], 0);

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
        peers: Arc::new(RwLock::new(Vec::new())),
        revoked_keys: Arc::new(RwLock::new(std::collections::HashSet::new())),
        keypair: Arc::new(RwLock::new(AgentKeypair::generate())),
        pending_keypair: Arc::new(RwLock::new(None)),
        relay_cancel: Arc::new(Notify::new()),
        config_path: None,
        shared_sink: make_shared_sink(),
        shared_sessions: make_shared_sessions(),
        shared_pending: make_shared_pending(),
        noise_keypair: make_noise_keypair(),
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
    assert_eq!(json["peers_count"], 0);
    assert_eq!(json["revoked_count"], 0);
    assert_eq!(json["online_peers"], 0);

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
        axum::routing::post(|| async { Json(serde_json::json!({ "api_token": "tok-from-cp" })) }),
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
        peers: Arc::new(RwLock::new(Vec::new())),
        revoked_keys: Arc::new(RwLock::new(std::collections::HashSet::new())),
        keypair: Arc::new(RwLock::new(AgentKeypair::generate())),
        pending_keypair: Arc::new(RwLock::new(None)),
        relay_cancel: Arc::new(Notify::new()),
        config_path: None,
        shared_sink: make_shared_sink(),
        shared_sessions: make_shared_sessions(),
        shared_pending: make_shared_pending(),
        noise_keypair: make_noise_keypair(),
    };
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({ "device_code": "dev-code-abc" })).unwrap();
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
        peers: Arc::new(RwLock::new(Vec::new())),
        revoked_keys: Arc::new(RwLock::new(std::collections::HashSet::new())),
        keypair: Arc::new(RwLock::new(AgentKeypair::generate())),
        pending_keypair: Arc::new(RwLock::new(None)),
        relay_cancel: Arc::new(Notify::new()),
        config_path: None,
        shared_sink: make_shared_sink(),
        shared_sessions: make_shared_sessions(),
        shared_pending: make_shared_pending(),
        noise_keypair: make_noise_keypair(),
    };
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({ "device_code": "dev-code-xyz" })).unwrap();
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

// ── proxy_to_cp_raw: no Authorization header ─────────────────────────────

#[tokio::test]
async fn proxy_register_with_key_does_not_send_bearer() {
    let dir = temp_mesh_dir("proxy-register-with-key");

    // Mock CP for /register-with-key: verify no Authorization header is present.
    let cp_base = mock_cp_server(
        axum::routing::post(|headers: axum::http::HeaderMap| async move {
            // Authorization header must be absent.
            let has_auth = headers.get(axum::http::header::AUTHORIZATION).is_some();
            assert!(
                !has_auth,
                "Authorization header must NOT be sent for /register-with-key"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "agent_card": {},
                    "api_token": "at_new_token"
                })),
            )
        }),
        "/register-with-key",
    )
    .await;

    // Token is set in state, but proxy_to_cp_raw must not forward it.
    let state = make_state(
        Some(cp_base),
        Some("tok-should-not-forward".into()),
        dir.clone(),
    );
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({
        "setup_key": "sk_test",
        "agent_id": "agent-1",
        "name": "Test Agent",
        "capabilities": []
    }))
    .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/register-with-key")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn proxy_register_with_key_returns_503_without_cp_url() {
    let dir = temp_mesh_dir("proxy-register-no-cp");
    // No cp_url configured
    let state = make_state(None, None, dir.clone());
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({"setup_key": "sk_x"})).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/register-with-key")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    std::fs::remove_dir_all(&dir).unwrap();
}

// ── setup-keys proxy ──────────────────────────────────────────────────────

#[tokio::test]
async fn proxy_setup_keys_list_forwards_bearer() {
    let dir = temp_mesh_dir("proxy-setup-keys-list");
    let cp_base = mock_cp_server(
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(auth, "Bearer tok-test");
            Json(serde_json::json!([{"id": "sk-1"}]))
        }),
        "/setup-keys",
    )
    .await;

    let state = make_state(Some(cp_base), Some("tok-test".into()), dir.clone());
    let app = router(state);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/setup-keys")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    std::fs::remove_dir_all(&dir).unwrap();
}

// ── ACL proxy ────────────────────────────────────────────────────────────

#[tokio::test]
async fn proxy_acl_list_forwards_bearer_to_cp() {
    let dir = temp_mesh_dir("proxy-acl-list");
    let cp_base = mock_cp_server(
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(auth, "Bearer tok-acl");
            Json(serde_json::json!([{"id": "rule-1"}]))
        }),
        "/acl",
    )
    .await;

    let state = make_state(Some(cp_base), Some("tok-acl".into()), dir.clone());
    let app = router(state);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/acl")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json[0]["id"], "rule-1");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn proxy_acl_create_forwards_body_and_bearer() {
    let dir = temp_mesh_dir("proxy-acl-create");
    let cp_base = mock_cp_server(
        axum::routing::post(
            |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| async move {
                let auth = headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert_eq!(auth, "Bearer tok-acl");
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({"id": body["source"]})),
                )
            },
        ),
        "/acl",
    )
    .await;

    let state = make_state(Some(cp_base), Some("tok-acl".into()), dir.clone());
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({
        "source": "agent-a",
        "target": "agent-b",
        "allowed_capabilities": ["cap1"]
    }))
    .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/acl")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn proxy_acl_delete_forwards_id_and_bearer() {
    let dir = temp_mesh_dir("proxy-acl-delete");
    let cp_base = mock_cp_server(
        axum::routing::delete(|headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert_eq!(auth, "Bearer tok-acl");
            StatusCode::NO_CONTENT
        }),
        "/acl/{id}",
    )
    .await;

    let state = make_state(Some(cp_base), Some("tok-acl".into()), dir.clone());
    let app = router(state);

    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri("/acl/rule-abc")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

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

// ── Rotation endpoint tests ───────────────────────────────────────────────

#[tokio::test]
async fn rotate_initiate_returns_503_without_peers() {
    // No peers → card_id lookup fails → 503.
    let dir = temp_mesh_dir("rotate-no-peers");
    let state = make_state(
        Some("http://cp.test".into()),
        Some("tok-abc".into()),
        dir.clone(),
    );
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({})).unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/rotate")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn rotate_complete_returns_409_without_pending() {
    // No pending keypair → 409 Conflict.
    let dir = temp_mesh_dir("rotate-complete-no-pending");
    let state = make_state(
        Some("http://cp.test".into()),
        Some("tok-abc".into()),
        dir.clone(),
    );
    let app = router(state);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/rotate/complete")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    std::fs::remove_dir_all(&dir).unwrap();
}

// ── POST /request ─────────────────────────────────────────────────────────

/// When relay is disconnected (shared_sink is None), POST /request returns 503.
#[tokio::test]
async fn mesh_request_returns_503_when_relay_not_connected() {
    let dir = temp_mesh_dir("mesh-request-503");
    let state = make_state(None, None, dir.clone());
    // shared_sink is None by default in make_state.
    let app = router(state);

    let body = serde_json::to_vec(&serde_json::json!({
        "target": "agent-target-id",
        "capability": "echo"
    }))
    .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/request")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// POST /request with missing required fields returns 422.
#[tokio::test]
async fn mesh_request_returns_422_for_invalid_body() {
    let dir = temp_mesh_dir("mesh-request-422");
    let state = make_state(None, None, dir.clone());
    let app = router(state);

    // Missing required `capability` field.
    let body = serde_json::to_vec(&serde_json::json!({
        "target": "agent-target-id"
    }))
    .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/request")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    std::fs::remove_dir_all(&dir).unwrap();
}
