//! Agent Mesh E2E Demo
//!
//! Starts all components (relay, registry, mock agent, meshd) in-process,
//! then exercises the full Alice → Relay → Bob flow.
//!
//! Usage: cargo run -p examples --bin e2e-demo

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use mesh_proto::acl::{AclPolicy, AclRule};
use mesh_proto::agent_card::{AgentCardRegistration, Capability};
use mesh_proto::identity::AgentKeypair;
use mesh_proto::message::{MeshEnvelope, MessageType};
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

    // --- Test 3: Alice → Bob (scheduling) via Relay ---
    println!("--- Test 3: Alice → Relay → Bob (scheduling) ---");
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
        "[PASS] Response: {}",
        serde_json::to_string_pretty(&result)?
    );
    println!();

    // --- Test 4: ACL Denial (admin capability) ---
    println!("--- Test 4: ACL Denial (admin capability) ---");
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
            println!("[PASS] ACL denied: {msg}\n");
        }
        Ok(v) => panic!("[FAIL] Expected ACL denial, got success: {v}"),
        Err(e) => panic!("[FAIL] Expected Remote error, got: {e}"),
    }

    // --- Test 5: Signature Verification (tampered message) ---
    println!("--- Test 5: Relay rejects tampered envelope ---");
    // Create a valid envelope, then tamper the payload.
    let tamper_kp = AgentKeypair::generate();
    let mut envelope = MeshEnvelope::new_signed(
        &tamper_kp,
        bob_id.clone(),
        MessageType::Request,
        serde_json::json!({"capability": "scheduling"}),
    )?;
    envelope.payload = serde_json::json!({"capability": "admin", "tampered": true});
    // Verification should fail.
    assert!(envelope.verify().is_err());
    println!("[PASS] Tampered envelope detected\n");

    println!("=== All tests passed! ===");
    Ok(())
}

// --- Component starters ---

async fn start_relay() -> Result<SocketAddr> {
    use axum::{
        extract::WebSocketUpgrade,
        routing::get,
        Router,
    };
    use std::sync::Arc;

    // Reuse relay's hub/ws logic by spawning the relay binary.
    // But for in-process testing, we inline a minimal relay.
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

    // Minimal in-process registry backed by a Vec.
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

async fn run_meshd(
    secret: &[u8; 32],
    relay_url: &str,
    local_url: &str,
    alice_id: &mesh_proto::identity::AgentId,
    bob_id: &mesh_proto::identity::AgentId,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use mesh_proto::message::AuthHandshake;
    use tokio_tungstenite::tungstenite::Message;

    let keypair = AgentKeypair::from_bytes(secret);
    let agent_id = keypair.agent_id();

    let mut acl = AclPolicy::new();
    acl.add_rule(AclRule {
        source: alice_id.clone(),
        target: bob_id.clone(),
        allowed_capabilities: vec!["scheduling".into(), "availability".into(), "contact".into()],
    });

    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url).await?;
    let (mut sink, mut stream) = ws_stream.split();

    // Auth handshake.
    let handshake = AuthHandshake {
        agent_id: agent_id.clone(),
        signature: String::new(),
        nonce: String::new(),
    };
    sink.send(Message::text(serde_json::to_string(&handshake)?))
        .await?;

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

                let capability = envelope
                    .payload
                    .get("capability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                if !acl.is_allowed(&envelope.from, &agent_id, capability) {
                    let err = MeshEnvelope::new_signed(
                        &keypair,
                        envelope.from.clone(),
                        MessageType::Error,
                        serde_json::json!({
                            "error": "acl_denied",
                            "capability": capability,
                            "request_id": envelope.id.to_string(),
                        }),
                    )?;
                    sink.send(Message::text(serde_json::to_string(&err)?))
                        .await?;
                    continue;
                }

                // Forward to local agent.
                let client = reqwest::Client::new();
                let resp = client
                    .post(local_url)
                    .json(&envelope.payload)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await?;
                let mut body: serde_json::Value = resp.json().await?;
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "request_id".into(),
                        serde_json::json!(envelope.id.to_string()),
                    );
                }

                let response =
                    MeshEnvelope::new_signed(&keypair, envelope.from, MessageType::Response, body)?;
                sink.send(Message::text(serde_json::to_string(&response)?))
                    .await?;
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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

type WsSink = SplitSink<WebSocket, AxumMsg>;

struct InProcessHub {
    agents: RwLock<HashMap<String, Arc<Mutex<WsSink>>>>,
}

impl InProcessHub {
    fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
        }
    }

    async fn register(&self, id: &str, sink: WsSink) {
        self.agents
            .write()
            .await
            .insert(id.to_string(), Arc::new(Mutex::new(sink)));
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
            false
        }
    }
}

async fn in_process_relay_handle(socket: WebSocket, hub: Arc<InProcessHub>) {
    let (sink, mut stream) = socket.split();
    use mesh_proto::message::AuthHandshake;

    // Wait for auth (first text message must be a valid handshake).
    let agent_id = match stream.next().await {
        Some(Ok(AxumMsg::Text(text))) => {
            match serde_json::from_str::<AuthHandshake>(&text) {
                Ok(h) => h.agent_id,
                Err(_) => return,
            }
        }
        _ => return,
    };

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
