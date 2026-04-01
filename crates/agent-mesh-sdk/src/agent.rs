use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use agent_mesh_core::message::{MeshEnvelope, MessageType};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::connection::{
    attempt_resume, challenge_response_auth, decrypt_envelope_payload, MeshConnection, PendingMap,
    SessionMap, StreamPendingMap, WsSink, WsStream,
};
use crate::error::SdkError;

/// A stream of JSON values yielded by a streaming handler.
pub type ValueStream =
    Pin<Box<dyn futures_util::Stream<Item = serde_json::Value> + Send + 'static>>;

/// Cancellation token for request handlers.
///
/// Check `is_cancelled()` periodically in long-running handlers to support
/// early termination when the client cancels or times out.
#[derive(Clone)]
pub struct CancelToken {
    rx: tokio::sync::watch::Receiver<bool>,
}

impl CancelToken {
    fn new() -> (CancelNotifier, Self) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (CancelNotifier(tx), Self { rx })
    }

    /// Returns true if the request has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Wait until cancelled. Completes immediately if already cancelled.
    pub async fn cancelled(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        let _ = self.rx.changed().await;
    }
}

/// Internal handle to trigger cancellation.
struct CancelNotifier(tokio::sync::watch::Sender<bool>);

impl CancelNotifier {
    fn cancel(&self) {
        let _ = self.0.send(true);
    }
}

/// Handler for incoming requests.
///
/// Implement this trait to define how the agent responds to requests.
/// Override `handle_stream` to support streaming responses.
/// The `cancel` token allows checking if the client has cancelled the request.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    async fn handle(
        &self,
        from: &AgentId,
        payload: &serde_json::Value,
        cancel: CancelToken,
    ) -> serde_json::Value;

    /// Handle a streaming request. Returns a stream of JSON chunks.
    /// Default: wraps `handle()` as a single-item stream.
    async fn handle_stream(
        &self,
        from: &AgentId,
        payload: &serde_json::Value,
        cancel: CancelToken,
    ) -> ValueStream {
        let val = self.handle(from, payload, cancel).await;
        Box::pin(futures_util::stream::once(async move { val }))
    }
}

/// Async function handler — convenience wrapper.
#[async_trait::async_trait]
impl<F, Fut> RequestHandler for F
where
    F: Fn(AgentId, serde_json::Value) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = serde_json::Value> + Send + 'static,
{
    async fn handle(
        &self,
        from: &AgentId,
        payload: &serde_json::Value,
        _cancel: CancelToken,
    ) -> serde_json::Value {
        (self)(from.clone(), payload.clone()).await
    }
}

/// A bidirectional mesh agent that can both send requests and handle incoming requests.
///
/// Replaces the need for a separate `meshd` daemon. The agent connects to the relay,
/// authenticates, and processes incoming messages including Noise handshakes, ACL checks,
/// and request handling — all within the SDK.
pub struct MeshAgent {
    conn: MeshConnection,
    acl: Arc<RwLock<AclPolicy>>,
}

impl MeshAgent {
    /// Connect to the relay, authenticate, and start handling incoming requests.
    pub async fn connect(
        keypair: AgentKeypair,
        relay_url: &str,
        acl: AclPolicy,
        handler: Arc<dyn RequestHandler>,
    ) -> Result<Self, SdkError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let (mut sink, mut stream) = ws_stream.split();

        let session_token_value = challenge_response_auth(&keypair, &mut sink, &mut stream).await?;
        let session_token = Arc::new(Mutex::new(session_token_value));

        let noise_keypair =
            Arc::new(NoiseKeypair::generate().map_err(|e| SdkError::Protocol(e.to_string()))?);
        let keypair = Arc::new(keypair);

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let stream_pending: StreamPendingMap = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::new(Mutex::new(sink));
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let acl = Arc::new(RwLock::new(acl));

        // Spawn the bidirectional reader loop with auto-reconnect.
        tokio::spawn(agent_reader_loop_with_reconnect(
            Arc::clone(&keypair),
            relay_url.to_string(),
            stream,
            Arc::clone(&noise_keypair),
            Arc::clone(&pending),
            Arc::clone(&stream_pending),
            Arc::clone(&sink),
            Arc::clone(&sessions),
            Arc::clone(&acl),
            handler,
            Arc::clone(&session_token),
        ));

        Ok(Self {
            conn: MeshConnection {
                keypair,
                noise_keypair,
                pending,
                stream_pending,
                sink,
                sessions,
            },
            acl,
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

    /// Send a plaintext request (no encryption).
    pub async fn request_plaintext(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        self.conn.request_plaintext(target, payload, timeout).await
    }

    /// Send an encrypted request and receive a streaming response.
    pub async fn request_stream(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<crate::StreamReceiver, SdkError> {
        self.conn.request_stream(target, payload, timeout).await
    }

    pub fn agent_id(&self) -> AgentId {
        self.conn.agent_id()
    }

    /// Update the ACL policy at runtime.
    pub async fn update_acl(&self, new_acl: AclPolicy) {
        *self.acl.write().await = new_acl;
    }
}

// --- Agent-specific reader loop ---

/// Peer Noise session state (for responder side).
#[allow(dead_code)]
enum PeerNoise {
    Handshaking(Box<NoiseHandshake>),
    Established(NoiseTransport),
}

/// Bidirectional reader loop wrapper with auto-reconnect.
#[allow(clippy::too_many_arguments)]
async fn agent_reader_loop_with_reconnect(
    keypair: Arc<AgentKeypair>,
    relay_url: String,
    stream: futures_util::stream::SplitStream<WsStream>,
    noise_keypair: Arc<NoiseKeypair>,
    pending: PendingMap,
    stream_pending: StreamPendingMap,
    sink: Arc<Mutex<WsSink>>,
    sessions: SessionMap,
    acl: Arc<RwLock<AclPolicy>>,
    handler: Arc<dyn RequestHandler>,
    session_token: Arc<Mutex<Option<String>>>,
) {
    agent_reader_loop(
        stream,
        Arc::new(keypair.as_ref().clone_inner()),
        Arc::clone(&noise_keypair),
        Arc::clone(&pending),
        Arc::clone(&stream_pending),
        Arc::clone(&sink),
        Arc::clone(&sessions),
        Arc::clone(&acl),
        Arc::clone(&handler),
    )
    .await;

    let token = {
        let guard = session_token.lock().await;
        guard.clone()
    };

    if let Some(token) = token {
        tracing::info!("agent connection lost, attempting session resumption");
        match attempt_resume(&keypair, &relay_url, &token).await {
            Ok((new_stream, new_sink_inner, new_token)) => {
                *sink.lock().await = new_sink_inner;
                *session_token.lock().await = Some(new_token);
                sessions.lock().await.clear();

                tracing::info!("agent session resumed successfully");

                agent_reader_loop(
                    new_stream,
                    Arc::new(keypair.as_ref().clone_inner()),
                    noise_keypair,
                    pending,
                    stream_pending,
                    sink,
                    sessions,
                    acl,
                    handler,
                )
                .await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "agent session resume failed");
            }
        }
    }
}

/// Agent reader loop: handles responses, Noise handshakes (responder), ACL, and request dispatch.
#[allow(clippy::too_many_arguments)]
async fn agent_reader_loop(
    mut stream: futures_util::stream::SplitStream<WsStream>,
    keypair: Arc<AgentKeypair>,
    noise_keypair: Arc<NoiseKeypair>,
    pending: PendingMap,
    stream_pending: StreamPendingMap,
    sink: Arc<Mutex<WsSink>>,
    sessions: SessionMap,
    acl: Arc<RwLock<AclPolicy>>,
    handler: Arc<dyn RequestHandler>,
) {
    let mut handshake_states: HashMap<String, PeerNoise> = HashMap::new();
    let mut cancel_tokens: HashMap<Uuid, CancelNotifier> = HashMap::new();

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let envelope: MeshEnvelope = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if envelope.verify().is_err() {
                    tracing::warn!("agent: envelope signature verification failed");
                    continue;
                }

                // Handle Cancel messages.
                if envelope.msg_type == MessageType::Cancel {
                    if let Some(reply_to) = envelope.in_reply_to {
                        if let Some(notifier) = cancel_tokens.remove(&reply_to) {
                            notifier.cancel();
                            tracing::debug!(
                                request_id = %reply_to,
                                from = envelope.from.as_str(),
                                "request cancelled by client"
                            );
                        }
                    }
                    continue;
                }

                // Dispatch responses to pending channels.
                if let Some(reply_to) = envelope.in_reply_to {
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

                    if envelope.msg_type == MessageType::StreamEnd {
                        let mut sp = stream_pending.lock().await;
                        sp.remove(&reply_to);
                        continue;
                    }

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

                    let mut p = pending.lock().await;
                    if let Some(tx) = p.remove(&reply_to) {
                        let _ = tx.send(envelope);
                        continue;
                    }
                }

                let peer_key = envelope.from.as_str().to_string();

                // Handle Noise handshake messages (responder side).
                if envelope.msg_type == MessageType::Handshake {
                    handle_handshake(
                        &envelope,
                        &peer_key,
                        &keypair,
                        &noise_keypair,
                        &sink,
                        &sessions,
                        &mut handshake_states,
                    )
                    .await;
                    continue;
                }

                // Decrypt payload if encrypted.
                let payload = if envelope.encrypted {
                    let mut sess = sessions.lock().await;
                    let transport = match sess.get_mut(&peer_key) {
                        Some(t) => t,
                        None => match handshake_states.get_mut(&peer_key) {
                            Some(PeerNoise::Established(t)) => t,
                            _ => {
                                tracing::warn!("encrypted msg but no session for {peer_key}");
                                continue;
                            }
                        },
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

                // ACL check.
                let capability = payload
                    .get("capability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let my_id = keypair.agent_id();

                if !acl
                    .read()
                    .await
                    .is_allowed(&envelope.from, &my_id, capability)
                {
                    tracing::warn!(
                        from = envelope.from.as_str(),
                        capability = capability,
                        "ACL denied"
                    );
                    let err_payload =
                        serde_json::json!({"error": "acl_denied", "capability": capability});
                    let _ = send_response(
                        &keypair,
                        &sink,
                        &sessions,
                        &peer_key,
                        envelope.from.clone(),
                        MessageType::Error,
                        Some(envelope.id),
                        err_payload,
                        envelope.encrypted,
                    )
                    .await;
                    continue;
                }

                // StreamRequest: call handle_stream, send chunks.
                if envelope.msg_type == MessageType::StreamRequest {
                    let (notifier, token) = CancelToken::new();
                    cancel_tokens.insert(envelope.id, notifier);
                    let mut val_stream =
                        handler.handle_stream(&envelope.from, &payload, token).await;
                    while let Some(chunk) = val_stream.next().await {
                        if !cancel_tokens.contains_key(&envelope.id) {
                            tracing::debug!("stream cancelled, stopping chunk emission");
                            break;
                        }
                        let _ = send_response(
                            &keypair,
                            &sink,
                            &sessions,
                            &peer_key,
                            envelope.from.clone(),
                            MessageType::StreamChunk,
                            Some(envelope.id),
                            chunk,
                            envelope.encrypted,
                        )
                        .await;
                    }
                    cancel_tokens.remove(&envelope.id);
                    let _ = send_response(
                        &keypair,
                        &sink,
                        &sessions,
                        &peer_key,
                        envelope.from,
                        MessageType::StreamEnd,
                        Some(envelope.id),
                        serde_json::Value::Null,
                        envelope.encrypted,
                    )
                    .await;
                    continue;
                }

                // Regular Request: call handler, send single response.
                let (notifier, token) = CancelToken::new();
                cancel_tokens.insert(envelope.id, notifier);
                let response_payload = handler.handle(&envelope.from, &payload, token).await;
                cancel_tokens.remove(&envelope.id);
                let _ = send_response(
                    &keypair,
                    &sink,
                    &sessions,
                    &peer_key,
                    envelope.from,
                    MessageType::Response,
                    Some(envelope.id),
                    response_payload,
                    envelope.encrypted,
                )
                .await;
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::warn!(error = %e, "agent ws read error");
                break;
            }
            _ => {}
        }
    }
}

// --- Agent-specific helpers ---

async fn handle_handshake(
    envelope: &MeshEnvelope,
    peer_key: &str,
    keypair: &Arc<AgentKeypair>,
    noise_keypair: &Arc<NoiseKeypair>,
    sink: &Arc<Mutex<WsSink>>,
    sessions: &SessionMap,
    handshake_states: &mut HashMap<String, PeerNoise>,
) {
    let hs_data = match envelope.payload.as_str() {
        Some(s) => s,
        None => return,
    };

    match handshake_states.get_mut(peer_key) {
        Some(PeerNoise::Handshaking(handshake)) => {
            // msg3: -> s, se
            if handshake.read_message(hs_data).is_err() {
                return;
            }
            let hs = match handshake_states.remove(peer_key) {
                Some(PeerNoise::Handshaking(h)) => *h,
                _ => return,
            };
            match hs.into_transport() {
                Ok(t) => {
                    sessions.lock().await.insert(peer_key.to_string(), t);
                    tracing::info!(peer = peer_key, "noise handshake complete (responder)");
                }
                Err(e) => {
                    tracing::warn!("noise transport: {e}");
                }
            }
        }
        _ => {
            // msg1: -> e (new handshake)
            let mut hs = match NoiseHandshake::new_responder(noise_keypair) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!("noise responder: {e}");
                    return;
                }
            };
            if hs.read_message(hs_data).is_err() {
                return;
            }
            let hs_reply = match hs.write_message() {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("noise write: {e}");
                    return;
                }
            };
            let reply = MeshEnvelope::new_signed_reply(
                keypair,
                envelope.from.clone(),
                MessageType::Handshake,
                Some(envelope.id),
                serde_json::Value::String(hs_reply),
            );
            if let Ok(reply) = reply {
                if let Ok(json) = serde_json::to_string(&reply) {
                    let mut s = sink.lock().await;
                    let _ = s.send(Message::text(json)).await;
                }
            }
            handshake_states.insert(peer_key.to_string(), PeerNoise::Handshaking(Box::new(hs)));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_response(
    keypair: &Arc<AgentKeypair>,
    sink: &Arc<Mutex<WsSink>>,
    sessions: &SessionMap,
    peer_key: &str,
    to: AgentId,
    msg_type: MessageType,
    in_reply_to: Option<Uuid>,
    payload: serde_json::Value,
    encrypt: bool,
) -> Result<(), String> {
    let response = if encrypt {
        let mut sess = sessions.lock().await;
        let transport = sess
            .get_mut(peer_key)
            .ok_or_else(|| format!("no noise session for {peer_key}"))?;
        let plaintext = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let ciphertext = transport.encrypt(&plaintext).map_err(|e| e.to_string())?;
        MeshEnvelope::new_encrypted(
            keypair,
            to,
            msg_type,
            in_reply_to,
            serde_json::Value::String(ciphertext),
        )
        .map_err(|e| e.to_string())?
    } else {
        MeshEnvelope::new_signed_reply(keypair, to, msg_type, in_reply_to, payload)
            .map_err(|e| e.to_string())?
    };

    let json = serde_json::to_string(&response).map_err(|e| e.to_string())?;
    let mut s = sink.lock().await;
    s.send(Message::text(json)).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_token_initially_not_cancelled() {
        let (_notifier, token) = CancelToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_token_becomes_cancelled() {
        let (notifier, token) = CancelToken::new();
        notifier.cancel();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn cancel_token_cancelled_future_completes() {
        let (notifier, mut token) = CancelToken::new();
        notifier.cancel();
        // Should complete immediately since already cancelled
        token.cancelled().await;
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn cancel_token_cancelled_future_waits() {
        let (notifier, mut token) = CancelToken::new();

        let handle = tokio::spawn(async move {
            token.cancelled().await;
            assert!(token.is_cancelled());
        });

        // Cancel after a brief delay
        tokio::task::yield_now().await;
        notifier.cancel();
        handle.await.unwrap();
    }

    #[test]
    fn cancel_notifier_drop_does_not_cancel() {
        let (notifier, token) = CancelToken::new();
        drop(notifier);
        // Dropping the notifier without calling cancel() should NOT cancel.
        // The watch channel sender is dropped, but the value remains false.
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_token_clone() {
        let (notifier, token) = CancelToken::new();
        let token2 = token.clone();
        notifier.cancel();
        assert!(token.is_cancelled());
        assert!(token2.is_cancelled());
    }
}
