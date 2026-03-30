use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use futures_util::SinkExt;
use mesh_proto::identity::AgentId;
use mesh_proto::message::{AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope};

use crate::hub::Hub;

pub async fn ws_handler(ws: WebSocketUpgrade, State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, hub))
}

async fn handle_connection(socket: WebSocket, hub: Arc<Hub>) {
    let (mut sink, mut stream) = socket.split();

    // Challenge-Response auth.
    let agent_id = match challenge_response_auth(&mut sink, &mut stream).await {
        Some(id) => id,
        None => {
            tracing::warn!("connection closed during auth");
            return;
        }
    };

    // Check if agent is revoked.
    if hub.is_revoked(&agent_id).await {
        tracing::warn!(
            agent = agent_id.as_str(),
            "revoked agent attempted to connect"
        );
        let _ = sink.send(axum::extract::ws::Message::Close(None)).await;
        return;
    }

    // Register with hub.
    hub.register(&agent_id, sink).await;

    // Process messages.
    while let Some(msg) = stream.next().await {
        // Any received frame counts as activity (including Pong).
        hub.touch(&agent_id).await;

        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_text_message(&hub, &agent_id, &text).await {
                    tracing::warn!(agent = agent_id.as_str(), error = %e, "message handling error");
                }
            }
            Ok(Message::Pong(_)) => {
                tracing::debug!(agent = agent_id.as_str(), "pong received");
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

/// 4-step challenge-response authentication.
async fn challenge_response_auth(
    sink: &mut SplitSink<WebSocket, Message>,
    stream: &mut SplitStream<WebSocket>,
) -> Option<AgentId> {
    // Step 1: Receive AuthHello from agent.
    let hello: AuthHello = match receive_json(stream).await {
        Some(h) => h,
        None => {
            tracing::warn!("auth: failed to receive AuthHello");
            return None;
        }
    };
    let agent_id = hello.agent_id;
    tracing::debug!(agent = agent_id.as_str(), "auth: received hello");

    // Step 2: Generate nonce and send AuthChallenge.
    let nonce = generate_nonce();
    let challenge = AuthChallenge {
        nonce: nonce.clone(),
    };
    if send_json(sink, &challenge).await.is_err() {
        tracing::warn!(agent = agent_id.as_str(), "auth: failed to send challenge");
        return None;
    }
    tracing::debug!(agent = agent_id.as_str(), "auth: sent challenge");

    // Step 3: Receive AuthResponse with signed nonce.
    let response: AuthResponse = match receive_json(stream).await {
        Some(r) => r,
        None => {
            tracing::warn!(
                agent = agent_id.as_str(),
                "auth: failed to receive response"
            );
            let _ = send_json(
                sink,
                &AuthResult {
                    success: false,
                    error: Some("no response".into()),
                },
            )
            .await;
            return None;
        }
    };

    // Verify the agent_id matches.
    if response.agent_id != agent_id {
        tracing::warn!("auth: agent_id mismatch in response");
        let _ = send_json(
            sink,
            &AuthResult {
                success: false,
                error: Some("agent_id mismatch".into()),
            },
        )
        .await;
        return None;
    }

    // Verify the signature over the nonce.
    match verify_nonce_signature(&agent_id, &nonce, &response.signature) {
        Ok(()) => {
            let _ = send_json(
                sink,
                &AuthResult {
                    success: true,
                    error: None,
                },
            )
            .await;
            tracing::info!(
                agent = agent_id.as_str(),
                "auth: challenge-response verified"
            );
            Some(agent_id)
        }
        Err(e) => {
            tracing::warn!(agent = agent_id.as_str(), error = %e, "auth: signature verification failed");
            let _ = send_json(
                sink,
                &AuthResult {
                    success: false,
                    error: Some(e),
                },
            )
            .await;
            None
        }
    }
}

fn generate_nonce() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn verify_nonce_signature(agent_id: &AgentId, nonce: &str, sig_b64: &str) -> Result<(), String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::Signature;

    let vk = agent_id
        .to_verifying_key()
        .map_err(|e| format!("bad agent_id: {e}"))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("bad sig base64: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    vk.verify(nonce.as_bytes(), &signature)
        .map_err(|e| format!("nonce signature invalid: {e}"))
}

async fn receive_json<T: serde::de::DeserializeOwned>(
    stream: &mut SplitStream<WebSocket>,
) -> Option<T> {
    match stream.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

async fn send_json<T: serde::Serialize>(
    sink: &mut SplitSink<WebSocket, Message>,
    value: &T,
) -> Result<(), ()> {
    let json = serde_json::to_string(value).map_err(|_| ())?;
    sink.send(Message::text(json)).await.map_err(|_| ())
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

    // Route to destination (with offline buffering).
    use crate::hub::RouteResult;
    match hub.route(&envelope).await {
        Ok(RouteResult::Delivered) => {
            tracing::debug!(
                from = sender.as_str(),
                to = envelope.to.as_str(),
                "message routed"
            );
            Ok(())
        }
        Ok(RouteResult::Buffered) => {
            tracing::debug!(
                from = sender.as_str(),
                to = envelope.to.as_str(),
                "target offline, message buffered"
            );
            Ok(())
        }
        Ok(RouteResult::BufferFull) => {
            tracing::warn!(
                from = sender.as_str(),
                to = envelope.to.as_str(),
                "target offline and buffer full"
            );
            Err(format!("target {} offline and buffer full", envelope.to))
        }
        Err(e) => Err(e),
    }
}
