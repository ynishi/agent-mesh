use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use agent_mesh_relay::hub::Hub;
use agent_mesh_sdk::{CancelToken, MeshAgent, MeshClient, RequestHandler};
use insta::assert_json_snapshot;

/// Start a relay on a random port and return (ws_url, http_base_url).
async fn start_relay() -> (String, String) {
    let hub = Arc::new(Hub::with_rate_limit(100.0, 200.0));
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

#[tokio::test]
async fn status_endpoint_empty() {
    let (_ws, http) = start_relay().await;

    let resp: serde_json::Value = reqwest::get(format!("{http}/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_json_snapshot!(resp);
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
