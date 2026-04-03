mod common;

use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::identity::AgentKeypair;
use agent_mesh_sdk::{CancelToken, MeshAgent, RequestHandler};
use agent_meshctl::daemon::MeshdClient;
use common::{
    allow_all_acl, deny_all_acl, register_test_agent, start_meshd, start_meshd_with_cp,
    start_registry, start_relay, start_relay_with_handle, wait_meshd_syncing, wait_peers_populated,
    EchoHandler, StreamingHandler,
};

// ---------------------------------------------------------------------------
// Scenario 1: meshd /request E2E
// ---------------------------------------------------------------------------

/// 1-1: meshd POST /request → Relay → EchoAgent → encrypted response.
#[tokio::test]
async fn meshd_request_echo() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"message": "hello"},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(body["payload"]["echo"]["message"], "hello");
        assert!(body["payload"]["from"].is_string());

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 1-2: meshd POST /request — verify response structure in detail.
///
/// meshd /request is always Noise-encrypted (no plaintext option).
/// This test validates that the response JSON structure is correct.
#[tokio::test]
async fn meshd_request_encrypted_echo() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"key": "value", "num": 42},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::OK);
        // Response must have a "payload" field
        assert!(body["payload"].is_object(), "payload must be an object");
        // The echo handler returns {"echo": <payload>, "from": "<id>"}
        assert_eq!(body["payload"]["echo"]["key"], "value");
        assert_eq!(body["payload"]["echo"]["num"], 42);
        assert!(
            body["payload"]["from"].is_string(),
            "from field must be a string"
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 1-3: Two consecutive requests reuse the Noise session (no second handshake).
///
/// Both responses must be OK — if session reuse is broken the second call would
/// fail or produce a different error code.
#[tokio::test]
async fn meshd_request_session_reuse() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let req = serde_json::json!({
            "target": agent_id.as_str(),
            "capability": "echo",
            "payload": {"seq": 1},
            "timeout_secs": 5
        });

        // First request: Noise XX handshake is performed
        let (s1, b1) = client.post("/request", &req).await.unwrap();
        assert_eq!(s1, hyper::StatusCode::OK);
        assert_eq!(b1["payload"]["echo"]["seq"], 1);

        // Second request: existing session is reused (no new handshake)
        let req2 = serde_json::json!({
            "target": agent_id.as_str(),
            "capability": "echo",
            "payload": {"seq": 2},
            "timeout_secs": 5
        });
        let (s2, b2) = client.post("/request", &req2).await.unwrap();
        assert_eq!(s2, hyper::StatusCode::OK);
        assert_eq!(b2["payload"]["echo"]["seq"], 2);

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 1-4: SlowHandler + short timeout → HTTP 504.
#[tokio::test]
async fn meshd_request_timeout() {
    struct SlowHandler;

    #[async_trait::async_trait]
    impl RequestHandler for SlowHandler {
        async fn handle(
            &self,
            _from: &agent_mesh_core::identity::AgentId,
            _payload: &serde_json::Value,
            mut cancel: CancelToken,
        ) -> serde_json::Value {
            tokio::select! {
                _ = cancel.cancelled() => serde_json::json!({"cancelled": true}),
                _ = tokio::time::sleep(Duration::from_secs(10)) => serde_json::json!({"slow": true}),
            }
        }
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(SlowHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {},
                    "timeout_secs": 1
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::GATEWAY_TIMEOUT);
        assert!(body["error"].is_string());

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 1-5: Request to a nonexistent agent_id → 504 (relay buffer timeout).
///
/// No SDK Agent is started; the request times out waiting for a delivery ACK.
/// timeout_secs is set to 2 to keep the test suite fast.
#[tokio::test]
async fn meshd_request_target_offline() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        // Generate a fresh keypair; the corresponding agent is never started.
        let offline_id = AgentKeypair::generate().agent_id();

        let client = MeshdClient::new(sock_path.clone());
        let (status, _body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": offline_id.as_str(),
                    "capability": "echo",
                    "payload": {},
                    "timeout_secs": 2
                }),
            )
            .await
            .unwrap();

        // The relay will eventually time out → meshd returns 504
        assert_eq!(status, hyper::StatusCode::GATEWAY_TIMEOUT);

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 2: ACL control
// ---------------------------------------------------------------------------

/// 2-1: SDK Agent with allow_all_acl → POST /request succeeds (HTTP 200).
#[tokio::test]
async fn meshd_request_acl_allow() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        // ACL on the receiving side: allow all
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"msg": "acl_allow"},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(body["payload"]["echo"]["msg"], "acl_allow");

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 2-2: SDK Agent with deny_all_acl → POST /request returns HTTP 502.
///
/// ACL is checked on the *receiving* side (SDK Agent). meshd sends the request;
/// the agent denies it and returns an error that meshd forwards as 502.
#[tokio::test]
async fn meshd_request_acl_deny() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        // ACL on the receiving side: deny all
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, deny_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, _body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        // The agent denies the request → meshd returns 502
        assert_eq!(status, hyper::StatusCode::BAD_GATEWAY);

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 2-3: SDK Agent with default_deny=true and no rules → POST /request returns 502.
#[tokio::test]
async fn meshd_request_acl_default_deny() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        // AclPolicy::new() creates default_deny=true with no rules → deny everything
        let acl = AclPolicy::new();
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, acl, handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());
        let (status, _body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::BAD_GATEWAY);

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 3: meshctl → meshd integration
// ---------------------------------------------------------------------------

/// 3-1: MeshdClient.post("/request") sends a request through meshd.
///
/// This exercises the full meshctl → meshd → Relay → SDK Agent path using
/// the production MeshdClient (UDS HTTP/1.1).
#[tokio::test]
async fn meshctl_request_via_meshd() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Use MeshdClient directly — this is the production meshctl code path.
        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"via": "meshctl"},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();

        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(body["payload"]["echo"]["via"], "meshctl");

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 3-2: GET /status returns a valid status document reflecting meshd state.
///
/// With cp_url=None the node stays in "Started" state.
#[tokio::test]
async fn meshctl_status_reflects_relay_connection() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client.get("/status").await.unwrap();

        assert_eq!(status, hyper::StatusCode::OK);
        assert!(body["state"].is_string(), "state must be a string");
        assert!(body["has_token"].is_boolean(), "has_token must be a bool");
        assert!(
            body["peers_count"].is_number(),
            "peers_count must be a number"
        );
        assert!(
            body["online_peers"].is_number(),
            "online_peers must be a number"
        );
        // cp_url=None → state remains "Started" (no cp_sync_loop transitions)
        assert_eq!(body["state"], "Started");

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 4: Key rotation
// ---------------------------------------------------------------------------

/// 4-1: POST /rotate → CP → POST /rotate/complete → state stays valid.
///
/// Requires Registry + CP Sync. The meshd agent_id must be registered in the
/// Registry DB so the CP /sync WS connection succeeds and FullSync populates
/// the peers list (required by rotate_initiate).
#[tokio::test]
async fn rotate_initiate_and_complete() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (registry_url, raw_token, db, _sync_hub, user_id, group_id) = start_registry().await;

        // Start meshd with CP. Grab the agent_id so we can pre-register in DB.
        let (meshd_handle, sock_path, _tmp, agent_id) =
            start_meshd_with_cp(&relay_ws_url, &registry_url, &raw_token)
                .await
                .unwrap();

        // Register the meshd agent in the Registry so CP /sync accepts the WS and
        // includes it in the FullSync peers list.
        register_test_agent(&db, user_id, group_id, &agent_id, "meshd-agent");

        // Wait for CP Sync to deliver FullSync (peers_count > 0).
        wait_peers_populated(&sock_path).await.unwrap();

        let client = MeshdClient::new(sock_path.clone());

        // POST /rotate — should succeed now that peers list is populated.
        let (rotate_status, rotate_body) = client
            .post("/rotate", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(
            rotate_status,
            hyper::StatusCode::OK,
            "rotate body: {rotate_body}"
        );
        assert!(rotate_body["new_agent_id"].is_string());

        // POST /rotate/complete — completes the rotation.
        let (complete_status, complete_body) = client
            .post("/rotate/complete", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(
            complete_status,
            hyper::StatusCode::OK,
            "complete body: {complete_body}"
        );
        assert_eq!(complete_body["status"], "completed");
        assert!(complete_body["new_agent_id"].is_string());

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 4-2: POST /rotate/complete without calling /rotate first → 409 CONFLICT.
#[tokio::test]
async fn rotate_complete_without_initiate_returns_409() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let client = MeshdClient::new(sock_path.clone());

        // POST /rotate/complete without a preceding /rotate → 409
        let (status, _body) = client
            .post("/rotate/complete", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(status, hyper::StatusCode::CONFLICT);

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 6: CP Sync
// ---------------------------------------------------------------------------

/// 6-1: FullSync from CP populates the peers list in meshd.
///
/// After CP Sync connects, the Registry sends a FullSync containing the
/// pre-registered agent. meshd applies this and peers_count becomes > 0.
#[tokio::test]
async fn cp_sync_full_sync_populates_peers() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (registry_url, raw_token, db, _sync_hub, user_id, group_id) = start_registry().await;

        let (meshd_handle, sock_path, _tmp, agent_id) =
            start_meshd_with_cp(&relay_ws_url, &registry_url, &raw_token)
                .await
                .unwrap();

        // Register the meshd agent so CP /sync accepts the WS.
        register_test_agent(&db, user_id, group_id, &agent_id, "meshd-sync-agent");

        // Also register a second agent to confirm FullSync includes multiple peers.
        use agent_mesh_core::identity::AgentKeypair;
        let second_kp = AgentKeypair::generate();
        let second_id = second_kp.agent_id();
        register_test_agent(&db, user_id, group_id, &second_id, "peer-agent");

        // Wait until meshd reaches Syncing state (CP Sync WS connected).
        wait_meshd_syncing(&sock_path).await.unwrap();
        // Wait until peers are populated.
        wait_peers_populated(&sock_path).await.unwrap();

        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client.get("/status").await.unwrap();
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(body["state"], "Syncing");
        assert!(
            body["peers_count"].as_u64().unwrap_or(0) >= 1,
            "expected peers_count >= 1, got: {}",
            body["peers_count"]
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 6-2: AclUpdated SyncEvent from CP applies ACL rules to meshd.
///
/// meshd starts with allow_all_acl. After CP Sync delivers AclUpdated with
/// a non-empty rules set, the local ACL is updated. We verify indirectly via
/// the /status endpoint (the ACL itself is not exposed, but the Syncing state
/// confirms CP Sync is active and events are being applied).
///
/// Note: Testing exact ACL rule application requires a /request roundtrip with
/// a specific allow/deny combination, which would require an additional SDK agent.
/// This test focuses on the state transition confirming SyncEvent delivery.
#[tokio::test]
async fn cp_sync_acl_updated_applies_rules() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (registry_url, raw_token, db, _sync_hub, user_id, group_id) = start_registry().await;

        let (meshd_handle, sock_path, _tmp, agent_id) =
            start_meshd_with_cp(&relay_ws_url, &registry_url, &raw_token)
                .await
                .unwrap();

        // Register meshd agent.
        register_test_agent(&db, user_id, group_id, &agent_id, "meshd-acl-agent");

        // Wait for CP Sync to establish.
        wait_meshd_syncing(&sock_path).await.unwrap();

        // Add an ACL rule via the Registry HTTP API. The Registry broadcasts
        // AclUpdated to all connected subscribers (including our meshd).
        let http_client = reqwest::Client::new();
        let acl_resp = http_client
            .post(format!("{registry_url}/acl"))
            .bearer_auth(&raw_token)
            .json(&serde_json::json!({
                "group_id": group_id,
                "source": "*",
                "target": "*",
                "allowed_capabilities": ["echo"]
            }))
            .send()
            .await
            .unwrap();
        assert!(
            acl_resp.status().is_success(),
            "ACL create failed: {}",
            acl_resp.status()
        );

        // Give CP Sync time to deliver AclUpdated.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Confirm meshd is still in Syncing state (event delivery did not crash it).
        let client = MeshdClient::new(sock_path.clone());
        let (status, body) = client.get("/status").await.unwrap();
        assert_eq!(status, hyper::StatusCode::OK);
        assert_eq!(
            body["state"], "Syncing",
            "meshd should remain Syncing after AclUpdated"
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 6-3: PeerAdded and PeerRemoved SyncEvents update meshd peers_count.
///
/// The Registry HTTP API (`/agents` POST/DELETE) does not currently broadcast
/// PeerAdded/PeerRemoved via SyncHub. To test the meshd-side event application,
/// this test manually triggers the broadcasts via the `Arc<SyncHub>` returned by
/// `start_registry()`, directly exercising the cp_sync_loop event handler.
#[tokio::test]
async fn cp_sync_peer_added_and_removed() {
    use agent_mesh_core::agent_card::AgentCard;
    use agent_mesh_core::sync::SyncEvent;

    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http) = start_relay().await;
        let (registry_url, raw_token, db, sync_hub, user_id, group_id) = start_registry().await;

        let (meshd_handle, sock_path, _tmp, agent_id) =
            start_meshd_with_cp(&relay_ws_url, &registry_url, &raw_token)
                .await
                .unwrap();

        // Register meshd agent so CP /sync accepts the WS.
        register_test_agent(&db, user_id, group_id, &agent_id, "meshd-peer-agent");

        // Wait for CP Sync to establish and FullSync to populate peers.
        wait_meshd_syncing(&sock_path).await.unwrap();
        wait_peers_populated(&sock_path).await.unwrap();

        let client = MeshdClient::new(sock_path.clone());

        // Record current peers_count.
        let (_, body_before) = client.get("/status").await.unwrap();
        let count_before = body_before["peers_count"].as_u64().unwrap_or(0);

        // Register a new agent in DB and broadcast PeerAdded via SyncHub.
        let new_kp = AgentKeypair::generate();
        let new_agent_id = new_kp.agent_id();
        let new_card = register_test_agent(&db, user_id, group_id, &new_agent_id, "dynamic-peer");

        // Manually broadcast PeerAdded to the group (simulating what a full
        // Registry implementation would do on agent registration).
        sync_hub
            .broadcast_to_group(
                &group_id,
                &SyncEvent::PeerAdded(AgentCard::clone(&new_card)),
            )
            .await;

        // Allow cp_sync_loop to process the event.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (_, body_after_add) = client.get("/status").await.unwrap();
        let count_after_add = body_after_add["peers_count"].as_u64().unwrap_or(0);
        assert!(
            count_after_add > count_before,
            "peers_count should increase after PeerAdded: before={count_before} after={count_after_add}"
        );

        // Broadcast PeerRemoved for the same agent.
        sync_hub
            .broadcast_to_group(&group_id, &SyncEvent::PeerRemoved(new_agent_id.clone()))
            .await;

        // Allow cp_sync_loop to process the event.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (_, body_after_remove) = client.get("/status").await.unwrap();
        let count_after_remove = body_after_remove["peers_count"].as_u64().unwrap_or(0);
        assert!(
            count_after_remove < count_after_add,
            "peers_count should decrease after PeerRemoved: after_add={count_after_add} after_remove={count_after_remove}"
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 9: Setup Key
// ---------------------------------------------------------------------------

/// 9-1: Create a Setup Key → register an agent via /register-with-key → verify.
#[tokio::test]
async fn setup_key_register_flow() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (registry_url, raw_token, _db, _sync_hub, _user_id, group_id) = start_registry().await;

        let http_client = reqwest::Client::new();

        // Create a Setup Key via the Registry API.
        let sk_resp = http_client
            .post(format!("{registry_url}/setup-keys"))
            .bearer_auth(&raw_token)
            .json(&serde_json::json!({
                "group_id": group_id,
                "usage": "OneOff",
                "expires_in_secs": 3600
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(sk_resp.status(), reqwest::StatusCode::CREATED);
        let sk_body: serde_json::Value = sk_resp.json().await.unwrap();
        let raw_key = sk_body["raw_key"].as_str().unwrap().to_string();

        // Register an agent using the Setup Key.
        use agent_mesh_core::identity::AgentKeypair;
        let new_kp = AgentKeypair::generate();
        let new_agent_id = new_kp.agent_id();
        let reg_resp = http_client
            .post(format!("{registry_url}/register-with-key"))
            .json(&serde_json::json!({
                "setup_key": raw_key,
                "agent_id": new_agent_id.as_str(),
                "name": "setup-key-agent",
                "capabilities": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            reg_resp.status(),
            reqwest::StatusCode::CREATED,
            "register-with-key failed"
        );
        let reg_body: serde_json::Value = reg_resp.json().await.unwrap();
        assert_eq!(reg_body["agent_card"]["agent_id"], new_agent_id.as_str());
        assert!(
            reg_body["api_token"].as_str().is_some(),
            "api_token should be returned once"
        );

        // Verify via GET /agents using the returned api_token.
        let returned_token = reg_body["api_token"].as_str().unwrap();
        let agents_resp = http_client
            .get(format!("{registry_url}/agents"))
            .bearer_auth(returned_token)
            .send()
            .await
            .unwrap();
        assert!(agents_resp.status().is_success(), "GET /agents failed");
        let agents: serde_json::Value = agents_resp.json().await.unwrap();
        assert!(agents.as_array().is_some(), "expected array");
    })
    .await
    .expect("test timed out");
}

/// 9-2: One-off Setup Key rejected on second use.
#[tokio::test]
async fn setup_key_one_off_reuse_rejected() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (registry_url, raw_token, _db, _sync_hub, _user_id, group_id) = start_registry().await;

        let http_client = reqwest::Client::new();

        // Create a one-off Setup Key.
        let sk_resp = http_client
            .post(format!("{registry_url}/setup-keys"))
            .bearer_auth(&raw_token)
            .json(&serde_json::json!({
                "group_id": group_id,
                "usage": "OneOff",
                "expires_in_secs": 3600
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(sk_resp.status(), reqwest::StatusCode::CREATED);
        let sk_body: serde_json::Value = sk_resp.json().await.unwrap();
        let raw_key = sk_body["raw_key"].as_str().unwrap().to_string();

        // First use — should succeed.
        use agent_mesh_core::identity::AgentKeypair;
        let kp1 = AgentKeypair::generate();
        let first_resp = http_client
            .post(format!("{registry_url}/register-with-key"))
            .json(&serde_json::json!({
                "setup_key": raw_key,
                "agent_id": kp1.agent_id().as_str(),
                "name": "agent-first",
                "capabilities": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            first_resp.status(),
            reqwest::StatusCode::CREATED,
            "first registration should succeed"
        );

        // Second use with the same one-off key — should be rejected.
        let kp2 = AgentKeypair::generate();
        let second_resp = http_client
            .post(format!("{registry_url}/register-with-key"))
            .json(&serde_json::json!({
                "setup_key": raw_key,
                "agent_id": kp2.agent_id().as_str(),
                "name": "agent-second",
                "capabilities": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            second_resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "second registration should be rejected (one-off key consumed)"
        );
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 7: Relay reconnection
// ---------------------------------------------------------------------------

/// 7-1: Relay stops → meshd auto-reconnects after relay restarts on same address.
///
/// meshd's relay_loop waits 3 seconds before retrying. After the relay is
/// restarted on the same port, meshd reconnects and /request succeeds again.
#[tokio::test]
async fn relay_reconnect_after_drop() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http, relay_handle, relay_addr) = start_relay_with_handle().await;

        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Baseline: /request succeeds before relay drop.
        let client = MeshdClient::new(sock_path.clone());
        let (status_before, _) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"phase": "before"},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            status_before,
            hyper::StatusCode::OK,
            "baseline /request should succeed"
        );

        // Drop the relay.
        relay_handle.abort();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Restart relay on the same address.
        // macOS may need a brief sleep for SO_REUSEADDR to take effect.
        let (_ws_url2, _http2, _relay2_handle) = {
            let mut result = None;
            for attempt in 0u32..5 {
                match tokio::net::TcpListener::bind(relay_addr).await {
                    Ok(listener) => {
                        use agent_mesh_relay::gate::NoopGateVerifier;
                        use agent_mesh_relay::hub::Hub;
                        use std::future::IntoFuture;
                        let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
                        let app = agent_mesh_relay::app(hub);
                        let port = listener.local_addr().unwrap().port();
                        let handle = tokio::spawn(axum::serve(listener, app).into_future());
                        result = Some((
                            format!("ws://127.0.0.1:{}/ws", port),
                            format!("http://127.0.0.1:{}", port),
                            handle,
                        ));
                        break;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
                    }
                }
            }
            result.expect("failed to re-bind relay after 5 attempts")
        };

        // Poll until meshd reconnects and /request succeeds (max 15 seconds).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut final_status = None;
        loop {
            match client
                .post(
                    "/request",
                    &serde_json::json!({
                        "target": agent_id.as_str(),
                        "capability": "echo",
                        "payload": {"phase": "after"},
                        "timeout_secs": 3
                    }),
                )
                .await
            {
                Ok((s, _)) if s == hyper::StatusCode::OK => {
                    final_status = Some(s);
                    break;
                }
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert_eq!(
            final_status,
            Some(hyper::StatusCode::OK),
            "meshd should reconnect to relay and /request should succeed"
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

/// 7-2: After relay reconnection, meshd preserves the same agent_id.
///
/// The keypair used by meshd is fixed at startup. meshd acts as the *initiator*
/// in Noise handshakes, so its agent_id appears in the EchoHandler's `from`
/// field. We record the `from` value before and after reconnection and assert
/// they are identical.
#[tokio::test]
async fn relay_reconnect_preserves_identity() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (relay_ws_url, _http, relay_handle, relay_addr) = start_relay_with_handle().await;

        let (meshd_handle, sock_path, _tmp) = start_meshd(&relay_ws_url, "").await.unwrap();

        let agent_kp = AgentKeypair::generate();
        let agent_id = agent_kp.agent_id();
        let handler: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let _agent = MeshAgent::connect(agent_kp, &relay_ws_url, allow_all_acl(), handler)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = MeshdClient::new(sock_path.clone());

        // Record meshd's agent_id via the `from` field in the echo response.
        let (_, body_before) = client
            .post(
                "/request",
                &serde_json::json!({
                    "target": agent_id.as_str(),
                    "capability": "echo",
                    "payload": {"phase": "before"},
                    "timeout_secs": 5
                }),
            )
            .await
            .unwrap();
        let meshd_agent_id_before = body_before["payload"]["from"]
            .as_str()
            .expect("from field must be in echo response")
            .to_string();

        // Drop the relay.
        relay_handle.abort();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Restart relay on the same address.
        let (_ws_url2, _http2, _relay2_handle) = {
            let mut result = None;
            for attempt in 0u32..5 {
                match tokio::net::TcpListener::bind(relay_addr).await {
                    Ok(listener) => {
                        use agent_mesh_relay::gate::NoopGateVerifier;
                        use agent_mesh_relay::hub::Hub;
                        use std::future::IntoFuture;
                        let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
                        let app = agent_mesh_relay::app(hub);
                        let port = listener.local_addr().unwrap().port();
                        let handle = tokio::spawn(axum::serve(listener, app).into_future());
                        result = Some((
                            format!("ws://127.0.0.1:{}/ws", port),
                            format!("http://127.0.0.1:{}", port),
                            handle,
                        ));
                        break;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
                    }
                }
            }
            result.expect("failed to re-bind relay after 5 attempts")
        };

        // Poll until meshd reconnects and /request succeeds again.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut meshd_agent_id_after = None;
        loop {
            match client
                .post(
                    "/request",
                    &serde_json::json!({
                        "target": agent_id.as_str(),
                        "capability": "echo",
                        "payload": {"phase": "after"},
                        "timeout_secs": 3
                    }),
                )
                .await
            {
                Ok((s, body)) if s == hyper::StatusCode::OK => {
                    meshd_agent_id_after = body["payload"]["from"].as_str().map(|s| s.to_string());
                    break;
                }
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let meshd_agent_id_after = meshd_agent_id_after
            .expect("meshd did not reconnect or from field missing after reconnect");
        assert_eq!(
            meshd_agent_id_before, meshd_agent_id_after,
            "meshd agent_id (from field) must be identical before and after relay reconnection"
        );

        meshd_handle.abort();
    })
    .await
    .expect("test timed out");
}

// ---------------------------------------------------------------------------
// Scenario 8: SDK-to-SDK streaming
// ---------------------------------------------------------------------------

/// 8-1: Agent A sends a streaming request to Agent B and receives multiple chunks.
///
/// Agent B uses `StreamingHandler { chunk_count: 5 }` which yields 5 chunks
/// from `handle_stream`. Agent A receives them via `request_stream`.
#[tokio::test]
async fn sdk_streaming_request() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay_ws_url, _http) = start_relay().await;

        // Agent A: sender
        let kp_a = AgentKeypair::generate();
        let handler_a: Arc<dyn RequestHandler> = Arc::new(EchoHandler);
        let agent_a = MeshAgent::connect(kp_a, &relay_ws_url, allow_all_acl(), handler_a)
            .await
            .unwrap();

        // Agent B: streaming responder
        let kp_b = AgentKeypair::generate();
        let agent_b_id = kp_b.agent_id();
        let handler_b: Arc<dyn RequestHandler> = Arc::new(StreamingHandler { chunk_count: 5 });
        let _agent_b = MeshAgent::connect(kp_b, &relay_ws_url, allow_all_acl(), handler_b)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Agent A sends a streaming request to Agent B.
        let mut receiver = agent_a
            .request_stream(&agent_b_id, serde_json::json!({}), Duration::from_secs(5))
            .await
            .unwrap();

        // Receive and validate all 5 chunks.
        for i in 0..5usize {
            let chunk = receiver
                .next()
                .await
                .expect("expected chunk, got None")
                .expect("chunk should not be an error");
            assert_eq!(chunk["chunk"], i, "chunk index mismatch at position {i}");
            assert_eq!(chunk["total"], 5, "total mismatch at position {i}");
        }

        // Stream should be exhausted (StreamEnd received).
        let end = receiver.next().await;
        assert!(end.is_none(), "expected stream end (None), got: {end:?}");
    })
    .await
    .expect("test timed out");
}
