//! Agent Mesh Demo
//!
//! Starts all components (relay, registry, mock agent, meshd) in-process,
//! then exercises the full Alice → Relay → Bob flow with E2E encryption.
//!
//! Usage: cargo run -p examples --bin mesh-demo

use std::collections::HashMap;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::{AclPolicy, AclRule};
use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::AgentKeypair;
use agent_mesh_core::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    println!("=== Agent Mesh Demo ===\n");

    // --- Generate keypairs ---
    let bob_kp = AgentKeypair::generate();
    let alice_kp = AgentKeypair::generate();
    let bob_id = bob_kp.agent_id();
    let alice_id = alice_kp.agent_id();
    println!("[setup] Bob ID: {bob_id}");
    println!("[setup] Alice ID: {alice_id}");

    // --- Start Relay (using agent-mesh-relay crate) ---
    let relay_addr = start_relay().await?;
    let relay_ws_url = format!("ws://{relay_addr}/ws");
    println!("[relay] listening on {relay_addr}");

    // --- Start Registry (using agent-mesh-registry crate) ---
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

    // --- Register Bob's Agent Card ---
    println!("--- Register Bob's Agent Card ---");
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
    println!("[ok] Agent card registered\n");

    // --- Discover agents ---
    println!("--- Discover agents with 'scheduling' capability ---");
    let resp = client
        .get(format!("{registry_url}/agents?capability=scheduling"))
        .send()
        .await?;
    let agents: serde_json::Value = resp.json().await?;
    let count = agents.as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(count, 1, "expected 1 agent, got {count}");
    println!("[ok] Found {count} agent(s)\n");

    // --- Alice → Relay → Bob (E2E encrypted request) ---
    println!("--- Send encrypted request: Alice -> Relay -> Bob ---");
    let mesh_client = agent_mesh_sdk::MeshClient::connect(alice_kp, &relay_ws_url)
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
    assert_eq!(result.get("agent").and_then(|v| v.as_str()), Some("bob"));
    assert_eq!(
        result.get("capability").and_then(|v| v.as_str()),
        Some("scheduling")
    );
    println!("[ok] Response: {}", serde_json::to_string_pretty(&result)?);
    println!();

    println!("=== Demo complete! ===");
    Ok(())
}

// --- Component starters ---

/// Start the relay using the real agent-mesh-relay crate.
async fn start_relay() -> Result<SocketAddr> {
    let hub = Arc::new(agent_mesh_relay::hub::Hub::new(
        100.0,
        200.0,
        Arc::new(agent_mesh_relay::gate::NoopGateVerifier),
    ));
    let app = agent_mesh_relay::app(hub);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(axum::serve(listener, app).into_future());
    Ok(addr)
}

/// Start the registry using the real agent-mesh-registry crate.
async fn start_registry() -> Result<SocketAddr> {
    let db = Arc::new(agent_mesh_registry::db::Database::open(":memory:")?);
    let state = agent_mesh_registry::AppState {
        db,
        oauth_config: None,
        http_client: reqwest::Client::new(),
        sync_hub: std::sync::Arc::new(agent_mesh_registry::sync::SyncHub::new()),
    };
    let app = agent_mesh_registry::app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(axum::serve(listener, app).into_future());
    Ok(addr)
}

/// Start a mock local agent that echoes requests.
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
    tokio::spawn(axum::serve(listener, app).into_future());
    Ok(addr)
}

/// Inline meshd with Noise E2E encryption support.
async fn run_meshd(
    secret: &[u8; 32],
    relay_url: &str,
    local_url: &str,
    alice_id: &agent_mesh_core::identity::AgentId,
    bob_id: &agent_mesh_core::identity::AgentId,
) -> Result<()> {
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
