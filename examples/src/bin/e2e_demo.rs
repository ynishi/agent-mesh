//! Agent Mesh E2E Demo
//!
//! Starts all components (relay, registry, mock agent, meshd) in-process,
//! then exercises the full Alice → Relay → Bob flow with E2E encryption.
//!
//! Usage: cargo run -p examples --bin e2e-demo

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use mesh_proto::acl::{AclPolicy, AclRule};
use mesh_proto::agent_card::{AgentCardRegistration, Capability};
use mesh_proto::identity::AgentKeypair;
use mesh_proto::message::{MeshEnvelope, MessageType};
use mesh_proto::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    println!("=== Agent Mesh E2E Demo ===\n");

    // --- Generate keypairs ---
    let bob_kp = AgentKeypair::generate();
    let alice_kp = AgentKeypair::generate();
    let bob_id = bob_kp.agent_id();
    let alice_id = alice_kp.agent_id();
    println!("[setup] Bob ID: {bob_id}");
    println!("[setup] Alice ID: {alice_id}");

    // --- Start Relay ---
    let relay_addr = start_relay().await?;
    let relay_ws_url = format!("ws://{relay_addr}/ws");
    println!("[relay] listening on {relay_addr}");

    // --- Start Registry ---
    let registry_addr = start_registry().await?;
    let registry_url = format!("http://{registry_addr}");
    println!("[registry] listening on {registry_addr}");

    // --- Start Mock Local Agent (Bob backend) ---
    let mock_addr = start_mock_agent().await?;
    println!("[mock-agent] listening on {mock_addr}");

    // --- Start meshd (Bob node) ---
    let bob_secret = *bob_kp.secret_bytes();
    let meshd_relay_url = relay_ws_url.clone();
    let meshd_local_url = format!("http://{mock_addr}");
    let alice_id_for_acl = alice_id.clone();
    let bob_id_for_acl = bob_id.clone();
    tokio::spawn(async move {
        run_meshd(
            &bob_secret,
            &meshd_relay_url,
            &meshd_local_url,
            &alice_id_for_acl,
            &bob_id_for_acl,
        )
        .await
    });
    // Wait for meshd to connect to relay.
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("[meshd] connected to relay\n");

    // --- Test 1: Register Agent Card ---
    println!("--- Test 1: Register Bob Agent Card ---");
    let client = reqwest::Client::new();
    let reg = AgentCardRegistration {
        agent_id: bob_id.clone(),
        name: "Bob".into(),
        description: Some("Local scheduling agent".into()),
        capabilities: vec![
            Capability {
                name: "scheduling".into(),
                description: None,
                input_schema: None,
                output_schema: None,
            },
            Capability {
                name: "availability".into(),
                description: None,
                input_schema: None,
                output_schema: None,
            },
            Capability {
                name: "contact".into(),
                description: None,
                input_schema: None,
                output_schema: None,
            },
        ],
        metadata: None,
    };
    let resp = client
        .post(format!("{registry_url}/agents"))
        .json(&reg)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "registration failed: {}",
        resp.status()
    );
    println!("[PASS] Agent card registered\n");

    // --- Test 2: Discover Agent ---
    println!("--- Test 2: Discover agents with 'scheduling' capability ---");
    let resp = client
        .get(format!("{registry_url}/agents?capability=scheduling"))
        .send()
        .await?;
    let agents: serde_json::Value = resp.json().await?;
    let count = agents.as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(count, 1, "expected 1 agent, got {count}");
    println!("[PASS] Found {count} agent(s)\n");

    // --- Test 3: Alice → Bob (encrypted scheduling request) ---
    println!("--- Test 3: Alice → Relay → Bob (E2E encrypted) ---");
    let mesh_client = mesh_sdk::MeshClient::connect(alice_kp, &relay_ws_url)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = mesh_client
        .request(
            &bob_id,
            serde_json::json!({"capability": "scheduling", "action": "list"}),
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("request: {e}"))?;
    assert_eq!(
        result.get("agent").and_then(|v| v.as_str()),
        Some("bob")
    );
    assert_eq!(
        result.get("capability").and_then(|v| v.as_str()),
        Some("scheduling")
    );
    println!(
        "[PASS] Encrypted response: {}",
        serde_json::to_string_pretty(&result)?
    );
    println!();

    // --- Test 4: Second request reuses Noise session (no new handshake) ---
    println!("--- Test 4: Second request reuses Noise session ---");
    let result2 = mesh_client
        .request(
            &bob_id,
            serde_json::json!({"capability": "availability", "action": "check"}),
            Duration::from_secs(5),
        )
        .await
        .map_err(|e| anyhow::anyhow!("request2: {e}"))?;
    assert_eq!(
        result2.get("agent").and_then(|v| v.as_str()),
        Some("bob")
    );
    println!("[PASS] Session reuse works\n");

    // --- Test 5: ACL Denial (admin capability, encrypted channel) ---
    println!("--- Test 5: ACL Denial (admin capability) ---");
    let acl_result = mesh_client
        .request(
            &bob_id,
            serde_json::json!({"capability": "admin", "action": "delete_all"}),
            Duration::from_secs(5),
        )
        .await;
    match acl_result {
        Err(mesh_sdk::SdkError::Remote(msg)) => {
            assert!(
                msg.contains("acl_denied"),
                "expected acl_denied, got: {msg}"
            );
            println!("[PASS] ACL denied (encrypted): {msg}\n");
        }
        Ok(v) => panic!("[FAIL] Expected ACL denial, got success: {v}"),
        Err(e) => panic!("[FAIL] Expected Remote error, got: {e}"),
    }

    // --- Test 6: Message buffering (offline agent) ---
    println!("--- Test 6: Message buffering for offline agent ---");
    {
        let bob2_kp = AgentKeypair::generate();
        let alice2_kp = AgentKeypair::generate();
        let bob2_id = bob2_kp.agent_id();
        let bob2_secret = *bob2_kp.secret_bytes();
        let nc2_id_for_acl = alice2_kp.agent_id();
        let ic2_id_for_acl = bob2_id.clone();
        let ic2_id_for_req = bob2_id.clone();
        let relay_url2 = relay_ws_url.clone();
        let relay_url_buf = relay_ws_url.clone();
        let mock_url2 = format!("http://{mock_addr}");

        // Spawn request to Bob2 (offline). Relay will buffer it.
        let buffer_task = tokio::spawn(async move {
            let mc = mesh_sdk::MeshClient::connect(alice2_kp, &relay_url_buf)
                .await
                .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            mc.request_plaintext(
                &ic2_id_for_req,
                serde_json::json!({"capability": "scheduling", "action": "buffered"}),
                Duration::from_secs(10),
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
        });

        // Wait for message to be buffered.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now connect Bob2 — buffered message should be flushed.
        tokio::spawn(async move {
            run_meshd(
                &bob2_secret,
                &relay_url2,
                &mock_url2,
                &nc2_id_for_acl,
                &ic2_id_for_acl,
            )
            .await
        });

        let buffer_result = buffer_task
            .await
            .map_err(|e| anyhow::anyhow!("join: {e}"))?
            .map_err(|e| anyhow::anyhow!("buffered request: {e}"))?;
        assert_eq!(
            buffer_result.get("agent").and_then(|v| v.as_str()),
            Some("bob")
        );
        println!(
            "[PASS] Buffered message delivered after agent connected: {}",
            buffer_result
                .get("capability")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
    }
    println!();

    // --- Test 7: Signature Verification (tampered message) ---
    println!("--- Test 7: Relay rejects tampered envelope ---");
    let tamper_kp = AgentKeypair::generate();
    let mut envelope = MeshEnvelope::new_signed(
        &tamper_kp,
        bob_id.clone(),
        MessageType::Request,
        serde_json::json!({"capability": "scheduling"}),
    )?;
    envelope.payload = serde_json::json!({"capability": "admin", "tampered": true});
    assert!(envelope.verify().is_err());
    println!("[PASS] Tampered envelope detected\n");

    println!("=== All tests passed! ===");
    Ok(())
}

// --- Component starters ---

async fn start_relay() -> Result<SocketAddr> {
    use axum::{extract::WebSocketUpgrade, routing::get, Router};
    use std::sync::Arc;

    let hub = Arc::new(InProcessHub::new());
    let hub2 = Arc::clone(&hub);

    let app = Router::new()
        .route(
            "/ws",
            get(move |ws: WebSocketUpgrade| {
                let hub = Arc::clone(&hub2);
                async move { ws.on_upgrade(move |socket| in_process_relay_handle(socket, hub)) }
            }),
        )
        .route("/health", get(|| async { "ok" }));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(addr)
}

async fn start_registry() -> Result<SocketAddr> {
    use axum::{
        extract::Query,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use std::sync::Arc;

    let store = Arc::new(tokio::sync::Mutex::new(Vec::<
        mesh_proto::agent_card::AgentCard,
    >::new()));
    let store2 = Arc::clone(&store);

    let app = Router::new()
        .route(
            "/agents",
            post({
                let store = Arc::clone(&store);
                move |Json(reg): Json<AgentCardRegistration>| {
                    let store = Arc::clone(&store);
                    async move {
                        let now = chrono::Utc::now();
                        let card = mesh_proto::agent_card::AgentCard {
                            id: uuid::Uuid::new_v4(),
                            agent_id: reg.agent_id,
                            name: reg.name,
                            description: reg.description,
                            capabilities: reg.capabilities,
                            registered_at: now,
                            updated_at: now,
                            metadata: reg.metadata,
                        };
                        store.lock().await.push(card.clone());
                        (StatusCode::CREATED, Json(card))
                    }
                }
            }),
        )
        .route(
            "/agents",
            get({
                move |Query(q): Query<mesh_proto::agent_card::AgentCardQuery>| {
                    let store = Arc::clone(&store2);
                    async move {
                        let cards = store.lock().await;
                        let filtered: Vec<_> = cards
                            .iter()
                            .filter(|c| {
                                if let Some(ref cap) = q.capability {
                                    c.capabilities.iter().any(|cc| cc.name == *cap)
                                } else {
                                    true
                                }
                            })
                            .cloned()
                            .collect();
                        Json(filtered)
                    }
                }
            }),
        )
        .route("/health", get(|| async { "ok" }));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(addr)
}

async fn start_mock_agent() -> Result<SocketAddr> {
    use axum::{routing::post, Json, Router};

    let app = Router::new().route(
        "/",
        post(|Json(body): Json<serde_json::Value>| async move {
            let capability = body
                .get("capability")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Json(serde_json::json!({
                "status": "ok",
                "agent": "bob",
                "capability": capability,
                "data": {"meetings": ["10:00 standup", "14:00 review"]},
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(addr)
}

/// Inline meshd with Noise E2E encryption support.
async fn run_meshd(
    secret: &[u8; 32],
    relay_url: &str,
    local_url: &str,
    alice_id: &mesh_proto::identity::AgentId,
    bob_id: &mesh_proto::identity::AgentId,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use mesh_proto::message::{AuthChallenge, AuthHello, AuthResponse, AuthResult};
    use tokio_tungstenite::tungstenite::Message;

    let keypair = AgentKeypair::from_bytes(secret);
    let noise_keypair = NoiseKeypair::generate().map_err(|e| anyhow::anyhow!("noise: {e}"))?;
    let agent_id = keypair.agent_id();

    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: alice_id.clone(),
        target: bob_id.clone(),
        allowed_capabilities: vec!["scheduling".into(), "availability".into(), "contact".into()],
    });

    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url).await?;
    let (mut sink, mut stream) = ws_stream.split();

    // Challenge-Response auth.
    let hello = AuthHello {
        agent_id: agent_id.clone(),
    };
    sink.send(Message::text(serde_json::to_string(&hello)?))
        .await?;

    let challenge_text = match stream.next().await {
        Some(Ok(Message::Text(t))) => t,
        _ => return Err(anyhow::anyhow!("no challenge")),
    };
    let challenge: AuthChallenge = serde_json::from_str(&challenge_text)?;

    let sig = keypair.sign(challenge.nonce.as_bytes());
    let sig_b64 = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    };
    let auth_resp = AuthResponse {
        agent_id: agent_id.clone(),
        signature: sig_b64,
    };
    sink.send(Message::text(serde_json::to_string(&auth_resp)?))
        .await?;

    let result_text = match stream.next().await {
        Some(Ok(Message::Text(t))) => t,
        _ => return Err(anyhow::anyhow!("no auth result")),
    };
    let result: AuthResult = serde_json::from_str(&result_text)?;
    if !result.success {
        return Err(anyhow::anyhow!("auth failed: {:?}", result.error));
    }

    // Per-peer Noise sessions.
    enum PeerNoise {
        Handshaking(Box<NoiseHandshake>),
        Established(NoiseTransport),
    }
    let mut sessions: HashMap<String, PeerNoise> = HashMap::new();

    // Process messages.
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let envelope: MeshEnvelope = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if envelope.verify().is_err() {
                    tracing::warn!("meshd: signature verification failed");
                    continue;
                }

                let peer_key = envelope.from.as_str().to_string();

                // Handle Noise handshake.
                if envelope.msg_type == MessageType::Handshake {
                    let hs_data = match envelope.payload.as_str() {
                        Some(s) => s,
                        None => continue,
                    };

                    match sessions.get_mut(&peer_key) {
                        Some(PeerNoise::Handshaking(handshake)) => {
                            // msg3
                            if handshake.read_message(hs_data).is_err() {
                                continue;
                            }
                            let state = sessions.remove(&peer_key).unwrap();
                            let hs = match state {
                                PeerNoise::Handshaking(h) => *h,
                                _ => unreachable!(),
                            };
                            match hs.into_transport() {
                                Ok(t) => {
                                    sessions.insert(peer_key.clone(), PeerNoise::Established(t));
                                    tracing::info!(peer = peer_key, "noise handshake complete");
                                }
                                Err(e) => {
                                    tracing::warn!("noise transport: {e}");
                                }
                            }
                        }
                        _ => {
                            // msg1 - new handshake
                            let mut hs = match NoiseHandshake::new_responder(&noise_keypair) {
                                Ok(h) => h,
                                Err(e) => {
                                    tracing::warn!("noise responder: {e}");
                                    continue;
                                }
                            };
                            if hs.read_message(hs_data).is_err() {
                                continue;
                            }
                            let hs_reply = match hs.write_message() {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::warn!("noise write: {e}");
                                    continue;
                                }
                            };
                            let reply = MeshEnvelope::new_signed_reply(
                                &keypair,
                                envelope.from.clone(),
                                MessageType::Handshake,
                                Some(envelope.id),
                                serde_json::Value::String(hs_reply),
                            );
                            if let Ok(reply) = reply {
                                let json = serde_json::to_string(&reply).unwrap();
                                let _ = sink.send(Message::text(json)).await;
                            }
                            sessions.insert(peer_key, PeerNoise::Handshaking(Box::new(hs)));
                        }
                    }
                    continue;
                }

                // Decrypt payload if encrypted.
                let payload = if envelope.encrypted {
                    let transport = match sessions.get_mut(&peer_key) {
                        Some(PeerNoise::Established(t)) => t,
                        _ => {
                            tracing::warn!("encrypted msg but no session");
                            continue;
                        }
                    };
                    let ct = match envelope.payload.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    match transport.decrypt(ct) {
                        Ok(pt) => match serde_json::from_slice(&pt) {
                            Ok(v) => v,
                            Err(_) => continue,
                        },
                        Err(e) => {
                            tracing::warn!("decrypt: {e}");
                            continue;
                        }
                    }
                } else {
                    envelope.payload.clone()
                };

                let capability = payload
                    .get("capability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                if !acl.is_allowed(&envelope.from, &agent_id, capability) {
                    let err_payload = serde_json::json!({
                        "error": "acl_denied",
                        "capability": capability,
                    });
                    let err = if envelope.encrypted {
                        if let Some(PeerNoise::Established(t)) = sessions.get_mut(&peer_key) {
                            let pt = serde_json::to_vec(&err_payload).unwrap();
                            match t.encrypt(&pt) {
                                Ok(ct) => MeshEnvelope::new_encrypted(
                                    &keypair,
                                    envelope.from.clone(),
                                    MessageType::Error,
                                    Some(envelope.id),
                                    serde_json::Value::String(ct),
                                ),
                                Err(_) => continue,
                            }
                        } else {
                            continue;
                        }
                    } else {
                        MeshEnvelope::new_signed_reply(
                            &keypair,
                            envelope.from.clone(),
                            MessageType::Error,
                            Some(envelope.id),
                            err_payload,
                        )
                    };
                    if let Ok(err) = err {
                        let _ = sink
                            .send(Message::text(serde_json::to_string(&err).unwrap()))
                            .await;
                    }
                    continue;
                }

                // Forward to local agent.
                let http_client = reqwest::Client::new();
                let resp = http_client
                    .post(local_url)
                    .json(&payload)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await;
                let body: serde_json::Value = match resp {
                    Ok(r) => match r.json().await {
                        Ok(v) => v,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                let response = if envelope.encrypted {
                    if let Some(PeerNoise::Established(t)) = sessions.get_mut(&peer_key) {
                        let pt = serde_json::to_vec(&body).unwrap();
                        match t.encrypt(&pt) {
                            Ok(ct) => MeshEnvelope::new_encrypted(
                                &keypair,
                                envelope.from,
                                MessageType::Response,
                                Some(envelope.id),
                                serde_json::Value::String(ct),
                            ),
                            Err(_) => continue,
                        }
                    } else {
                        continue;
                    }
                } else {
                    MeshEnvelope::new_signed_reply(
                        &keypair,
                        envelope.from,
                        MessageType::Response,
                        Some(envelope.id),
                        body,
                    )
                };
                if let Ok(response) = response {
                    let _ = sink
                        .send(Message::text(serde_json::to_string(&response).unwrap()))
                        .await;
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!("meshd ws error: {e}");
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

// --- In-process relay ---

use axum::extract::ws::{Message as AxumMsg, WebSocket};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

type WsSink = SplitSink<WebSocket, AxumMsg>;

use std::collections::VecDeque;

struct InProcessHub {
    agents: RwLock<HashMap<String, Arc<Mutex<WsSink>>>>,
    buffers: RwLock<HashMap<String, VecDeque<String>>>,
}

impl InProcessHub {
    fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            buffers: RwLock::new(HashMap::new()),
        }
    }

    async fn register(&self, id: &str, sink: WsSink) {
        let sink = Arc::new(Mutex::new(sink));
        self.agents
            .write()
            .await
            .insert(id.to_string(), Arc::clone(&sink));

        // Flush buffered messages.
        let pending = {
            let mut buffers = self.buffers.write().await;
            buffers.remove(id)
        };
        if let Some(messages) = pending {
            let mut s = sink.lock().await;
            for msg in messages {
                let _ = s.send(AxumMsg::text(msg)).await;
            }
        }
    }

    async fn unregister(&self, id: &str) {
        self.agents.write().await.remove(id);
    }

    async fn route(&self, to: &str, msg: &str) -> bool {
        let agents = self.agents.read().await;
        if let Some(sink) = agents.get(to) {
            let mut sink = sink.lock().await;
            sink.send(AxumMsg::text(msg.to_string())).await.is_ok()
        } else {
            drop(agents);
            // Buffer for offline agent.
            let mut buffers = self.buffers.write().await;
            let queue = buffers.entry(to.to_string()).or_default();
            if queue.len() < 100 {
                queue.push_back(msg.to_string());
            }
            false
        }
    }
}

async fn in_process_relay_handle(socket: WebSocket, hub: Arc<InProcessHub>) {
    let (mut sink, mut stream) = socket.split();
    use mesh_proto::message::{AuthChallenge, AuthHello, AuthResponse, AuthResult};

    // Step 1: Receive AuthHello.
    let hello: AuthHello = match receive_axum_json(&mut stream).await {
        Some(h) => h,
        None => return,
    };
    let agent_id = hello.agent_id;

    // Step 2: Send AuthChallenge with random nonce.
    let nonce = uuid::Uuid::new_v4().to_string();
    let challenge = AuthChallenge {
        nonce: nonce.clone(),
    };
    if send_axum_json(&mut sink, &challenge).await.is_err() {
        return;
    }

    // Step 3: Receive AuthResponse and verify.
    let response: AuthResponse = match receive_axum_json(&mut stream).await {
        Some(r) => r,
        None => return,
    };
    if response.agent_id != agent_id {
        let _ = send_axum_json(
            &mut sink,
            &AuthResult {
                success: false,
                error: Some("id mismatch".into()),
            },
        )
        .await;
        return;
    }

    // Verify nonce signature.
    let verified = (|| -> Result<(), String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let vk = agent_id.to_verifying_key().map_err(|e| e.to_string())?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&response.signature)
            .map_err(|e| e.to_string())?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "bad sig len".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        use ed25519_dalek::Verifier;
        vk.verify(nonce.as_bytes(), &sig).map_err(|e| e.to_string())
    })();

    match verified {
        Ok(()) => {
            let _ = send_axum_json(
                &mut sink,
                &AuthResult {
                    success: true,
                    error: None,
                },
            )
            .await;
        }
        Err(e) => {
            let _ = send_axum_json(
                &mut sink,
                &AuthResult {
                    success: false,
                    error: Some(e),
                },
            )
            .await;
            return;
        }
    }

    let id_str = agent_id.as_str().to_string();
    hub.register(&id_str, sink).await;

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(AxumMsg::Text(text)) => {
                if let Ok(env) = serde_json::from_str::<MeshEnvelope>(&text) {
                    if env.from != agent_id {
                        continue;
                    }
                    if env.verify().is_err() {
                        continue;
                    }
                    hub.route(env.to.as_str(), &text).await;
                }
            }
            Ok(AxumMsg::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }

    hub.unregister(&id_str).await;
}

async fn receive_axum_json<T: serde::de::DeserializeOwned>(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<T> {
    match stream.next().await {
        Some(Ok(AxumMsg::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

async fn send_axum_json<T: serde::Serialize>(
    sink: &mut SplitSink<WebSocket, AxumMsg>,
    value: &T,
) -> Result<(), ()> {
    let json = serde_json::to_string(value).map_err(|_| ())?;
    sink.send(AxumMsg::text(json)).await.map_err(|_| ())
}
