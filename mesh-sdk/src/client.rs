use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use mesh_proto::identity::{AgentId, AgentKeypair};
use mesh_proto::message::{AuthHandshake, MeshEnvelope, MessageType};
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::error::SdkError;

type PendingMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<MeshEnvelope>>>>;

/// Mesh client for sending requests to remote agents through the relay.
/// Designed for use in both long-lived processes and short-lived edge functions.
pub struct MeshClient {
    keypair: Arc<AgentKeypair>,
    relay_url: String,
    pending: PendingMap,
    sink: Arc<
        Mutex<
            futures_util::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                Message,
            >,
        >,
    >,
}

impl MeshClient {
    /// Connect to the relay and authenticate.
    pub async fn connect(keypair: AgentKeypair, relay_url: &str) -> Result<Self, SdkError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let (mut sink, stream) = ws_stream.split();

        // Auth handshake.
        let handshake = AuthHandshake {
            agent_id: keypair.agent_id(),
            signature: String::new(),
            nonce: String::new(),
        };
        let json =
            serde_json::to_string(&handshake).map_err(|e| SdkError::Protocol(e.to_string()))?;
        sink.send(Message::text(json))
            .await
            .map_err(|e| SdkError::Auth(e.to_string()))?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::new(Mutex::new(sink));

        // Spawn reader task.
        let pending_clone = Arc::clone(&pending);
        tokio::spawn(reader_loop(stream, pending_clone));

        Ok(Self {
            keypair: Arc::new(keypair),
            relay_url: relay_url.to_string(),
            pending,
            sink,
        })
    }

    /// Send a request to a remote agent and wait for the response.
    pub async fn request(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        let envelope =
            MeshEnvelope::new_signed(&self.keypair, target.clone(), MessageType::Request, payload)
                .map_err(|e| SdkError::Protocol(e.to_string()))?;

        let msg_id = envelope.id;
        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().await;
            pending.insert(msg_id, tx);
        }

        let json =
            serde_json::to_string(&envelope).map_err(|e| SdkError::Protocol(e.to_string()))?;
        {
            let mut sink = self.sink.lock().await;
            sink.send(Message::text(json))
                .await
                .map_err(|e| SdkError::Send(e.to_string()))?;
        }

        // Wait for response with timeout.
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => {
                if response.msg_type == MessageType::Error {
                    Err(SdkError::Remote(response.payload.to_string()))
                } else {
                    Ok(response.payload)
                }
            }
            Ok(Err(_)) => Err(SdkError::Receive("response channel closed".into())),
            Err(_) => {
                // Clean up pending entry.
                let mut pending = self.pending.lock().await;
                pending.remove(&msg_id);
                Err(SdkError::Timeout)
            }
        }
    }

    pub fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }
}

async fn reader_loop(
    mut stream: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    pending: PendingMap,
) {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(envelope) = serde_json::from_str::<MeshEnvelope>(&text) {
                    // Match response to pending request by looking at the payload's request_id
                    // or by convention the envelope.id. For v0.1, we use a simple approach:
                    // the response envelope has a "request_id" field in payload.
                    let request_id = envelope
                        .payload
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok());

                    if let Some(rid) = request_id {
                        let mut pending = pending.lock().await;
                        if let Some(tx) = pending.remove(&rid) {
                            let _ = tx.send(envelope);
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!(error = %e, "ws read error");
                break;
            }
            _ => {}
        }
    }
}
