use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::identity::{AgentId, AgentKeypair};
use agent_mesh_core::message::{MeshEnvelope, MessageType};
use agent_mesh_core::noise::NoiseKeypair;
use futures_util::stream::StreamExt;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

use crate::connection::{
    attempt_resume, challenge_response_auth, decrypt_envelope_payload, MeshConnection, PendingMap,
    SessionMap, StreamPendingMap, WsSink, WsStream,
};
use crate::error::SdkError;
use crate::StreamReceiver;

/// Mesh client for sending requests to remote agents through the relay.
/// Automatically negotiates Noise_XX E2E encryption on first request to each target.
pub struct MeshClient {
    conn: MeshConnection,
    relay_url: String,
}

impl MeshClient {
    /// Connect to the relay and authenticate.
    pub async fn connect(keypair: AgentKeypair, relay_url: &str) -> Result<Self, SdkError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let (mut sink, mut stream) = ws_stream.split();

        let session_token_value = challenge_response_auth(&keypair, &mut sink, &mut stream).await?;
        let session_token = Arc::new(Mutex::new(session_token_value));

        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| SdkError::Protocol(e.to_string()))?;

        let keypair = Arc::new(keypair);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let stream_pending: StreamPendingMap = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::new(Mutex::new(sink));
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

        // Spawn reader task with auto-reconnect.
        tokio::spawn(reader_loop_with_reconnect(
            Arc::clone(&keypair),
            relay_url.to_string(),
            stream,
            Arc::clone(&pending),
            Arc::clone(&stream_pending),
            Arc::clone(&sessions),
            Arc::clone(&sink),
            Arc::clone(&session_token),
        ));

        Ok(Self {
            conn: MeshConnection {
                keypair,
                noise_keypair: Arc::new(noise_keypair),
                pending,
                stream_pending,
                sink,
                sessions,
            },
            relay_url: relay_url.to_string(),
        })
    }

    /// Send an encrypted request to a remote agent and wait for the response.
    pub async fn request(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        self.conn.request(target, payload, timeout).await
    }

    /// Send an encrypted request and receive a streaming response.
    pub async fn request_stream(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<StreamReceiver, SdkError> {
        self.conn.request_stream(target, payload, timeout).await
    }

    /// Send a plaintext request (no encryption). For backward compatibility.
    pub async fn request_plaintext(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        self.conn.request_plaintext(target, payload, timeout).await
    }

    pub fn agent_id(&self) -> AgentId {
        self.conn.agent_id()
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }
}

// --- Client-specific reader loop ---

/// Reader loop wrapper with auto-reconnect on disconnect.
#[allow(clippy::too_many_arguments)]
async fn reader_loop_with_reconnect(
    keypair: Arc<AgentKeypair>,
    relay_url: String,
    stream: futures_util::stream::SplitStream<WsStream>,
    pending: PendingMap,
    stream_pending: StreamPendingMap,
    sessions: SessionMap,
    sink: Arc<Mutex<WsSink>>,
    session_token: Arc<Mutex<Option<String>>>,
) {
    reader_loop(
        stream,
        Arc::clone(&pending),
        Arc::clone(&stream_pending),
        Arc::clone(&sessions),
    )
    .await;

    let token = {
        let token_guard = session_token.lock().await;
        token_guard.clone()
    };

    if let Some(token) = token {
        tracing::info!("connection lost, attempting session resumption");
        match attempt_resume(&keypair, &relay_url, &token).await {
            Ok((new_stream, new_sink_inner, new_token)) => {
                *sink.lock().await = new_sink_inner;
                *session_token.lock().await = Some(new_token);
                sessions.lock().await.clear();

                tracing::info!("session resumed successfully");

                reader_loop(new_stream, pending, stream_pending, sessions).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "session resume failed");
            }
        }
    }
}

/// Client reader loop: dispatches responses to pending request channels.
async fn reader_loop(
    mut stream: futures_util::stream::SplitStream<WsStream>,
    pending: PendingMap,
    stream_pending: StreamPendingMap,
    sessions: SessionMap,
) {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let envelope: MeshEnvelope = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let reply_to = match envelope.in_reply_to {
                    Some(id) => id,
                    None => continue,
                };

                // StreamChunk: forward decrypted payload to stream receiver.
                if envelope.msg_type == MessageType::StreamChunk {
                    let sp = stream_pending.lock().await;
                    if let Some(tx) = sp.get(&reply_to) {
                        let payload = if envelope.encrypted {
                            match decrypt_envelope_payload(&envelope, &sessions).await {
                                Ok(v) => v,
                                Err(e) => {
                                    let _ = tx.send(Err(e));
                                    continue;
                                }
                            }
                        } else {
                            envelope.payload
                        };
                        let _ = tx.send(Ok(payload));
                    }
                    continue;
                }

                // StreamEnd: close the stream channel.
                if envelope.msg_type == MessageType::StreamEnd {
                    let mut sp = stream_pending.lock().await;
                    sp.remove(&reply_to);
                    continue;
                }

                // Error for a stream request: send error and close.
                if envelope.msg_type == MessageType::Error {
                    let mut sp = stream_pending.lock().await;
                    if let Some(tx) = sp.remove(&reply_to) {
                        let err_msg = if envelope.encrypted {
                            match decrypt_envelope_payload(&envelope, &sessions).await {
                                Ok(v) => v.to_string(),
                                Err(e) => e.to_string(),
                            }
                        } else {
                            envelope.payload.to_string()
                        };
                        let _ = tx.send(Err(SdkError::Remote(err_msg)));
                        continue;
                    }
                    drop(sp);
                }

                // Regular response/handshake/error: deliver to oneshot pending.
                let mut p = pending.lock().await;
                if let Some(tx) = p.remove(&reply_to) {
                    let _ = tx.send(envelope);
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
