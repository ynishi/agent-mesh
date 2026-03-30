use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::stream::StreamExt;
use mesh_proto::identity::AgentId;
use mesh_proto::message::{AuthHandshake, MeshEnvelope};

use crate::hub::Hub;

pub async fn ws_handler(ws: WebSocketUpgrade, State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, hub))
}

async fn handle_connection(socket: WebSocket, hub: Arc<Hub>) {
    let (sink, mut stream) = socket.split();

    // Step 1: Wait for auth handshake.
    let agent_id = match wait_for_auth(&mut stream).await {
        Some(id) => id,
        None => {
            tracing::warn!("connection closed before auth");
            return;
        }
    };

    // Register with hub.
    hub.register(&agent_id, sink).await;

    // Step 2: Process messages.
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_text_message(&hub, &agent_id, &text).await {
                    tracing::warn!(agent = agent_id.as_str(), error = %e, "message handling error");
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!(agent = agent_id.as_str(), error = %e, "ws error");
                break;
            }
            _ => {}
        }
    }

    hub.unregister(&agent_id).await;
}

async fn wait_for_auth(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<AgentId> {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<AuthHandshake>(&text) {
                    Ok(handshake) => {
                        // v0.1: Accept the agent_id without challenge verification.
                        // Full challenge-response auth is v0.2.
                        tracing::info!(
                            agent = handshake.agent_id.as_str(),
                            "auth accepted (v0.1 trust-on-first-use)"
                        );
                        return Some(handshake.agent_id);
                    }
                    Err(e) => {
                        tracing::warn!("invalid auth handshake: {e}");
                        return None;
                    }
                }
            }
            Ok(Message::Close(_)) => return None,
            Err(_) => return None,
            _ => {}
        }
    }
    None
}

async fn handle_text_message(hub: &Hub, sender: &AgentId, text: &str) -> Result<(), String> {
    let envelope: MeshEnvelope =
        serde_json::from_str(text).map_err(|e| format!("parse envelope: {e}"))?;

    // Verify sender matches the authenticated agent.
    if envelope.from != *sender {
        return Err(format!(
            "sender mismatch: envelope from={} but authenticated as={}",
            envelope.from, sender
        ));
    }

    // Verify signature.
    envelope
        .verify()
        .map_err(|e| format!("signature verification failed: {e}"))?;

    // Route to destination.
    match hub.route(&envelope).await {
        Ok(true) => {
            tracing::debug!(
                from = sender.as_str(),
                to = envelope.to.as_str(),
                "message routed"
            );
            Ok(())
        }
        Ok(false) => {
            tracing::warn!(
                from = sender.as_str(),
                to = envelope.to.as_str(),
                "target not connected"
            );
            Err(format!("target {} not connected", envelope.to))
        }
        Err(e) => Err(e),
    }
}
