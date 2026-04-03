use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::{AclPolicy, AclRule};
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use agent_mesh_core::message::{MeshEnvelope, MessageType};
use agent_mesh_relay::gate::NoopGateVerifier;
use agent_mesh_relay::hub::Hub;
use agent_mesh_sdk::{CancelToken, MeshAgent, MeshClient, RequestHandler, ValueStream};

/// Start a relay on a random port and return (ws_url, http_base_url).
async fn start_relay() -> (String, String) {
    let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
    let app = agent_mesh_relay::app(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    (
        format!("ws://127.0.0.1:{}/ws", addr.port()),
        format!("http://127.0.0.1:{}", addr.port()),
    )
}

/// Simple echo handler for tests.
struct EchoHandler;

#[async_trait::async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(
        &self,
        from: &AgentId,
        payload: &serde_json::Value,
        _cancel: CancelToken,
    ) -> serde_json::Value {
        serde_json::json!({
            "echo": payload,
            "from": from.as_str(),
        })
    }
}

fn allow_all_acl() -> AclPolicy {
    AclPolicy {
        default_deny: false,
        rules: vec![],
    }
}

fn deny_all_acl() -> AclPolicy {
    AclPolicy {
        default_deny: true,
        rules: vec![],
    }
}

// --- HTTP endpoint tests ---

#[tokio::test]
async fn health_check() {
    let (_ws, http) = start_relay().await;

    let resp = reqwest::get(format!("{http}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// --- SDK integration tests ---

#[tokio::test]
async fn agent_connect_and_plaintext_request() {
    let (relay_url, _http) = start_relay().await;

    let agent_kp = AgentKeypair::generate();
    let agent_id = agent_kp.agent_id();
    let client_kp = AgentKeypair::generate();

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(agent_kp, &relay_url, allow_all_acl(), handler)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();

    let resp = client
        .request_plaintext(
            &agent_id,
            serde_json::json!({"capability": "echo", "message": "hello"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // Verify response has echo and from fields.
    assert_eq!(resp["echo"]["message"], "hello");
    assert!(resp["from"].is_string());
}

#[tokio::test]
async fn agent_connect_and_encrypted_request() {
    let (relay_url, _http) = start_relay().await;

    let agent_kp = AgentKeypair::generate();
    let agent_id = agent_kp.agent_id();
    let client_kp = AgentKeypair::generate();

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(agent_kp, &relay_url, allow_all_acl(), handler)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();

    // Encrypted request triggers Noise_XX handshake + encrypted payload.
    let resp = client
        .request(
            &agent_id,
            serde_json::json!({"capability": "echo", "data": "secret"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    assert_eq!(resp["echo"]["data"], "secret");
    assert!(resp["from"].is_string());
}

#[tokio::test]
async fn acl_deny_blocks_request() {
    let (relay_url, _http) = start_relay().await;

    let agent_kp = AgentKeypair::generate();
    let agent_id = agent_kp.agent_id();
    let client_kp = AgentKeypair::generate();

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(agent_kp, &relay_url, deny_all_acl(), handler)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();

    let result = client
        .request_plaintext(
            &agent_id,
            serde_json::json!({"capability": "echo", "message": "blocked"}),
            Duration::from_secs(5),
        )
        .await;

    assert!(result.is_err(), "ACL deny should reject the request");
}

#[tokio::test]
async fn multiple_agents_communicate() {
    let (relay_url, _http) = start_relay().await;

    let alice_kp = AgentKeypair::generate();
    let alice_id = alice_kp.agent_id();
    let bob_kp = AgentKeypair::generate();
    let bob_id = bob_kp.agent_id();

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let alice = MeshAgent::connect(alice_kp, &relay_url, allow_all_acl(), handler.clone())
        .await
        .unwrap();
    let bob = MeshAgent::connect(bob_kp, &relay_url, allow_all_acl(), handler)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice requests Bob.
    let resp = alice
        .request_plaintext(
            &bob_id,
            serde_json::json!({"capability": "echo", "from_alice": true}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(resp["echo"]["from_alice"], true);

    // Bob requests Alice.
    let resp = bob
        .request_plaintext(
            &alice_id,
            serde_json::json!({"capability": "echo", "from_bob": true}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(resp["echo"]["from_bob"], true);
}

// --- Session reuse (Noise handshake only on first request) ---

#[tokio::test]
async fn encrypted_session_reuse() {
    let (relay_url, _http) = start_relay().await;

    let agent_kp = AgentKeypair::generate();
    let agent_id = agent_kp.agent_id();
    let client_kp = AgentKeypair::generate();

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(agent_kp, &relay_url, allow_all_acl(), handler)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();

    // First request triggers Noise handshake.
    let resp1 = client
        .request(
            &agent_id,
            serde_json::json!({"capability": "echo", "seq": 1}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(resp1["echo"]["seq"], 1);

    // Second request reuses the session (no new handshake).
    let resp2 = client
        .request(
            &agent_id,
            serde_json::json!({"capability": "echo", "seq": 2}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(resp2["echo"]["seq"], 2);
}

// --- ACL with specific rules via MeshAgent ---

#[tokio::test]
async fn mesh_agent_acl_with_rules() {
    let (relay_url, _http) = start_relay().await;

    let server_kp = AgentKeypair::generate();
    let server_id = server_kp.agent_id();
    let client_kp = AgentKeypair::generate();
    let client_id = client_kp.agent_id();

    // Allow only "echo" capability.
    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: client_id.clone(),
        target: server_id.clone(),
        allowed_capabilities: vec!["echo".into()],
    });

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(server_kp, &relay_url, acl, handler)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();

    // Allowed capability succeeds.
    let resp = client
        .request(
            &server_id,
            serde_json::json!({"capability": "echo", "data": "ok"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(resp["echo"]["data"], "ok");

    // Denied capability fails.
    let result = client
        .request(
            &server_id,
            serde_json::json!({"capability": "admin", "action": "delete"}),
            Duration::from_secs(5),
        )
        .await;
    assert!(result.is_err());
}

// --- Message buffering for offline agent ---

#[tokio::test]
async fn message_buffering_offline_agent() {
    let (relay_url, _http) = start_relay().await;

    let agent_kp = AgentKeypair::generate();
    let agent_id = agent_kp.agent_id();
    let sender_kp = AgentKeypair::generate();

    // Connect sender first (agent is offline).
    let sender = MeshClient::connect(sender_kp, &relay_url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send plaintext request to offline agent (relay will buffer).
    let agent_id_clone = agent_id.clone();
    let send_task = tokio::spawn(async move {
        sender
            .request_plaintext(
                &agent_id_clone,
                serde_json::json!({"capability": "echo", "buffered": true}),
                Duration::from_secs(10),
            )
            .await
    });

    // Wait for message to be buffered.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Now connect the agent — buffered message should be flushed.
    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _agent = MeshAgent::connect(agent_kp, &relay_url, allow_all_acl(), handler)
        .await
        .unwrap();

    let result = send_task.await.unwrap().unwrap();
    assert_eq!(result["echo"]["buffered"], true);
}

// --- Tampered envelope signature verification ---

#[tokio::test]
async fn tampered_envelope_rejected() {
    let kp = AgentKeypair::generate();
    let target = AgentKeypair::generate().agent_id();

    let mut envelope = MeshEnvelope::new_signed(
        &kp,
        target,
        MessageType::Request,
        serde_json::json!({"capability": "scheduling"}),
    )
    .unwrap();

    // Tamper the payload after signing.
    envelope.payload = serde_json::json!({"capability": "admin", "tampered": true});
    assert!(envelope.verify().is_err());
}

// --- Streaming response ---

#[tokio::test]
async fn streaming_response() {
    let (relay_url, _http) = start_relay().await;

    let server_kp = AgentKeypair::generate();
    let server_id = server_kp.agent_id();
    let client_kp = AgentKeypair::generate();
    let client_id = client_kp.agent_id();

    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: client_id.clone(),
        target: server_id.clone(),
        allowed_capabilities: vec!["llm".into()],
    });

    struct StreamHandler;

    #[async_trait::async_trait]
    impl RequestHandler for StreamHandler {
        async fn handle(
            &self,
            _from: &AgentId,
            _payload: &serde_json::Value,
            _cancel: CancelToken,
        ) -> serde_json::Value {
            serde_json::json!({"error": "use streaming"})
        }

        async fn handle_stream(
            &self,
            _from: &AgentId,
            _payload: &serde_json::Value,
            _cancel: CancelToken,
        ) -> ValueStream {
            let tokens = vec![
                serde_json::json!({"token": "Hello"}),
                serde_json::json!({"token": " world"}),
                serde_json::json!({"token": "!"}),
            ];
            Box::pin(futures_util::stream::iter(tokens))
        }
    }

    let handler: Arc<dyn RequestHandler> = Arc::new(StreamHandler);
    let _server = MeshAgent::connect(server_kp, &relay_url, acl, handler)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream_rx = client
        .request_stream(
            &server_id,
            serde_json::json!({"capability": "llm", "prompt": "test"}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    let mut chunks = Vec::new();
    while let Some(result) = stream_rx.next().await {
        chunks.push(result.unwrap());
    }

    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0]["token"], "Hello");
    assert_eq!(chunks[1]["token"], " world");
    assert_eq!(chunks[2]["token"], "!");
}

// --- Request cancellation via timeout ---

#[tokio::test]
async fn request_cancellation_timeout() {
    let (relay_url, _http) = start_relay().await;

    let server_kp = AgentKeypair::generate();
    let server_id = server_kp.agent_id();
    let client_kp = AgentKeypair::generate();
    let client_id = client_kp.agent_id();

    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: client_id.clone(),
        target: server_id.clone(),
        allowed_capabilities: vec!["slow".into()],
    });

    use std::sync::atomic::{AtomicBool, Ordering};
    let was_cancelled = Arc::new(AtomicBool::new(false));
    let was_cancelled_clone = Arc::clone(&was_cancelled);

    struct SlowHandler {
        was_cancelled: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RequestHandler for SlowHandler {
        async fn handle(
            &self,
            _from: &AgentId,
            _payload: &serde_json::Value,
            mut cancel: CancelToken,
        ) -> serde_json::Value {
            tokio::select! {
                _ = cancel.cancelled() => {
                    self.was_cancelled.store(true, Ordering::SeqCst);
                    serde_json::json!({"cancelled": true})
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    serde_json::json!({"cancelled": false})
                }
            }
        }
    }

    let handler: Arc<dyn RequestHandler> = Arc::new(SlowHandler {
        was_cancelled: was_cancelled_clone,
    });
    let _server = MeshAgent::connect(server_kp, &relay_url, acl, handler)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Short timeout should cause cancellation.
    let result = client
        .request(
            &server_id,
            serde_json::json!({"capability": "slow"}),
            Duration::from_millis(500),
        )
        .await;
    assert!(result.is_err());
}

// --- Rate limiting ---

#[tokio::test]
async fn rate_limiting() {
    // Use a relay with a low rate limit.
    // Burst must be high enough for Noise handshake messages + a few requests.
    let hub = Arc::new(Hub::new(5.0, 8.0, Arc::new(NoopGateVerifier)));
    let app = agent_mesh_relay::app(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    let relay_url = format!("ws://127.0.0.1:{}/ws", addr.port());

    let server_kp = AgentKeypair::generate();
    let server_id = server_kp.agent_id();
    let client_kp = AgentKeypair::generate();
    let client_id = client_kp.agent_id();

    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: client_id.clone(),
        target: server_id.clone(),
        allowed_capabilities: vec!["test".into()],
    });

    let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
    let _server = MeshAgent::connect(server_kp, &relay_url, acl, handler)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = MeshClient::connect(client_kp, &relay_url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send many requests rapidly.
    let mut successes = 0u32;
    let mut failures = 0u32;
    for _ in 0..10 {
        match client
            .request(
                &server_id,
                serde_json::json!({"capability": "test"}),
                Duration::from_millis(1500),
            )
            .await
        {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    assert!(successes > 0, "at least some requests should succeed");
    assert!(failures > 0, "some requests should be rejected");
}
