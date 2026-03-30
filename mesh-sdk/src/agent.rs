use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use mesh_proto::acl::AclPolicy;
use mesh_proto::identity::{AgentId, AgentKeypair};
use mesh_proto::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use mesh_proto::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::error::SdkError;

type PendingMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<MeshEnvelope>>>>;
type SessionMap = Arc<Mutex<HashMap<String, NoiseTransport>>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Handler for incoming requests.
///
/// Implement this trait to define how the agent responds to requests.
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    async fn handle(&self, from: &AgentId, payload: &serde_json::Value) -> serde_json::Value;
}

/// Async function handler — convenience wrapper.
#[async_trait::async_trait]
impl<F, Fut> RequestHandler for F
where
    F: Fn(AgentId, serde_json::Value) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = serde_json::Value> + Send + 'static,
{
    async fn handle(&self, from: &AgentId, payload: &serde_json::Value) -> serde_json::Value {
        (self)(from.clone(), payload.clone()).await
    }
}

/// A bidirectional mesh agent that can both send requests and handle incoming requests.
///
/// Replaces the need for a separate `meshd` daemon. The agent connects to the relay,
/// authenticates, and processes incoming messages including Noise handshakes, ACL checks,
/// and request handling — all within the SDK.
pub struct MeshAgent {
    keypair: Arc<AgentKeypair>,
    noise_keypair: Arc<NoiseKeypair>,
    pending: PendingMap,
    sink: Arc<Mutex<WsSink>>,
    sessions: SessionMap,
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

        // Challenge-Response auth.
        let hello = AuthHello {
            agent_id: keypair.agent_id(),
        };
        let json = serde_json::to_string(&hello).map_err(|e| SdkError::Protocol(e.to_string()))?;
        sink.send(Message::text(json))
            .await
            .map_err(|e| SdkError::Auth(e.to_string()))?;

        let challenge: AuthChallenge = receive_ws_json(&mut stream)
            .await
            .ok_or_else(|| SdkError::Auth("no challenge received".into()))?;

        let sig = keypair.sign(challenge.nonce.as_bytes());
        let sig_b64 = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        };
        let response = AuthResponse {
            agent_id: keypair.agent_id(),
            signature: sig_b64,
        };
        let json =
            serde_json::to_string(&response).map_err(|e| SdkError::Protocol(e.to_string()))?;
        sink.send(Message::text(json))
            .await
            .map_err(|e| SdkError::Auth(e.to_string()))?;

        let result: AuthResult = receive_ws_json(&mut stream)
            .await
            .ok_or_else(|| SdkError::Auth("no auth result received".into()))?;
        if !result.success {
            return Err(SdkError::Auth(
                result.error.unwrap_or_else(|| "auth failed".into()),
            ));
        }

        let noise_keypair =
            Arc::new(NoiseKeypair::generate().map_err(|e| SdkError::Protocol(e.to_string()))?);
        let keypair = Arc::new(keypair);

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::new(Mutex::new(sink));
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let acl = Arc::new(RwLock::new(acl));

        // Spawn the bidirectional reader loop.
        tokio::spawn(agent_reader_loop(
            stream,
            Arc::new(keypair.as_ref().clone_inner()),
            Arc::clone(&noise_keypair),
            Arc::clone(&pending),
            Arc::clone(&sink),
            Arc::clone(&sessions),
            Arc::clone(&acl),
            handler,
        ));

        Ok(Self {
            keypair,
            noise_keypair,
            pending,
            sink,
            sessions,
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
        self.ensure_session(target, timeout).await?;

        let plaintext =
            serde_json::to_vec(&payload).map_err(|e| SdkError::Protocol(e.to_string()))?;
        let ciphertext_b64 = {
            let mut sessions = self.sessions.lock().await;
            let transport = sessions.get_mut(target.as_str()).ok_or_else(|| {
                SdkError::Protocol("noise session missing after handshake".into())
            })?;
            transport
                .encrypt(&plaintext)
                .map_err(|e| SdkError::Protocol(format!("encrypt: {e}")))?
        };

        let envelope = MeshEnvelope::new_encrypted(
            &self.keypair,
            target.clone(),
            MessageType::Request,
            None,
            serde_json::Value::String(ciphertext_b64),
        )
        .map_err(|e| SdkError::Protocol(e.to_string()))?;

        let msg_id = envelope.id;
        let response = self.send_and_wait(envelope, msg_id, timeout).await?;

        if response.msg_type == MessageType::Error {
            if response.encrypted {
                let decrypted = self.decrypt_payload(target, &response.payload).await?;
                return Err(SdkError::Remote(
                    String::from_utf8_lossy(&decrypted).to_string(),
                ));
            }
            return Err(SdkError::Remote(response.payload.to_string()));
        }

        if response.encrypted {
            let decrypted = self.decrypt_payload(target, &response.payload).await?;
            serde_json::from_slice(&decrypted).map_err(|e| SdkError::Protocol(e.to_string()))
        } else {
            Ok(response.payload)
        }
    }

    /// Send a plaintext request (no encryption).
    pub async fn request_plaintext(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        let envelope =
            MeshEnvelope::new_signed(&self.keypair, target.clone(), MessageType::Request, payload)
                .map_err(|e| SdkError::Protocol(e.to_string()))?;

        let msg_id = envelope.id;
        let response = self.send_and_wait(envelope, msg_id, timeout).await?;

        if response.msg_type == MessageType::Error {
            Err(SdkError::Remote(response.payload.to_string()))
        } else {
            Ok(response.payload)
        }
    }

    pub fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
    }

    /// Update the ACL policy at runtime.
    pub async fn update_acl(&self, new_acl: AclPolicy) {
        *self.acl.write().await = new_acl;
    }

    async fn ensure_session(&self, target: &AgentId, timeout: Duration) -> Result<(), SdkError> {
        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(target.as_str()) {
                return Ok(());
            }
        }

        let mut handshake = NoiseHandshake::new_initiator(&self.noise_keypair)
            .map_err(|e| SdkError::Protocol(format!("noise init: {e}")))?;

        let hs_data1 = handshake
            .write_message()
            .map_err(|e| SdkError::Protocol(format!("noise write msg1: {e}")))?;
        let msg1 = MeshEnvelope::new_signed(
            &self.keypair,
            target.clone(),
            MessageType::Handshake,
            serde_json::Value::String(hs_data1),
        )
        .map_err(|e| SdkError::Protocol(e.to_string()))?;
        let msg1_id = msg1.id;

        let msg2 = self.send_and_wait(msg1, msg1_id, timeout).await?;

        let hs_data2 = msg2
            .payload
            .as_str()
            .ok_or_else(|| SdkError::Protocol("handshake msg2 payload not a string".into()))?;
        handshake
            .read_message(hs_data2)
            .map_err(|e| SdkError::Protocol(format!("noise read msg2: {e}")))?;

        let hs_data3 = handshake
            .write_message()
            .map_err(|e| SdkError::Protocol(format!("noise write msg3: {e}")))?;
        let msg3 = MeshEnvelope::new_signed_reply(
            &self.keypair,
            target.clone(),
            MessageType::Handshake,
            Some(msg2.id),
            serde_json::Value::String(hs_data3),
        )
        .map_err(|e| SdkError::Protocol(e.to_string()))?;

        let json = serde_json::to_string(&msg3).map_err(|e| SdkError::Protocol(e.to_string()))?;
        {
            let mut sink = self.sink.lock().await;
            sink.send(Message::text(json))
                .await
                .map_err(|e| SdkError::Send(e.to_string()))?;
        }

        let transport = handshake
            .into_transport()
            .map_err(|e| SdkError::Protocol(format!("noise transport: {e}")))?;
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(target.as_str().to_string(), transport);
        }

        tracing::info!(target = target.as_str(), "noise handshake complete");
        Ok(())
    }

    async fn send_and_wait(
        &self,
        envelope: MeshEnvelope,
        msg_id: Uuid,
        timeout: Duration,
    ) -> Result<MeshEnvelope, SdkError> {
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

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(SdkError::Receive("response channel closed".into())),
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&msg_id);
                Err(SdkError::Timeout)
            }
        }
    }

    async fn decrypt_payload(
        &self,
        target: &AgentId,
        payload: &serde_json::Value,
    ) -> Result<Vec<u8>, SdkError> {
        let ciphertext = payload
            .as_str()
            .ok_or_else(|| SdkError::Protocol("encrypted payload not a string".into()))?;
        let mut sessions = self.sessions.lock().await;
        let transport = sessions
            .get_mut(target.as_str())
            .ok_or_else(|| SdkError::Protocol("no noise session for decrypt".into()))?;
        transport
            .decrypt(ciphertext)
            .map_err(|e| SdkError::Protocol(format!("decrypt: {e}")))
    }
}

/// Peer Noise session state (for responder side).
/// Established is never constructed as a variant — completed handshakes move
/// directly into the shared SessionMap. Kept for symmetry with meshd.
#[allow(dead_code)]
enum PeerNoise {
    Handshaking(Box<NoiseHandshake>),
    Established(NoiseTransport),
}

/// Bidirectional reader loop that handles:
/// 1. Response matching (in_reply_to → pending)
/// 2. Noise handshake (responder side)
/// 3. Incoming requests (ACL check → handler → response)
#[allow(clippy::too_many_arguments)]
async fn agent_reader_loop(
    mut stream: futures_util::stream::SplitStream<WsStream>,
    keypair: Arc<AgentKeypair>,
    noise_keypair: Arc<NoiseKeypair>,
    pending: PendingMap,
    sink: Arc<Mutex<WsSink>>,
    sessions: SessionMap,
    acl: Arc<RwLock<AclPolicy>>,
    handler: Arc<dyn RequestHandler>,
) {
    // Separate map for handshake-in-progress peers (not yet in sessions).
    let mut handshake_states: HashMap<String, PeerNoise> = HashMap::new();

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let envelope: MeshEnvelope = match serde_json::from_str(&text) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                // Verify signature.
                if envelope.verify().is_err() {
                    tracing::warn!("agent: envelope signature verification failed");
                    continue;
                }

                // If it's a response to a pending request, deliver it.
                if let Some(reply_to) = envelope.in_reply_to {
                    let mut p = pending.lock().await;
                    if let Some(tx) = p.remove(&reply_to) {
                        let _ = tx.send(envelope);
                        continue;
                    }
                }

                let peer_key = envelope.from.as_str().to_string();

                // Handle Noise handshake messages.
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
                        None => {
                            // Check handshake_states for established sessions.
                            match handshake_states.get_mut(&peer_key) {
                                Some(PeerNoise::Established(t)) => t,
                                _ => {
                                    tracing::warn!("encrypted msg but no session for {peer_key}");
                                    continue;
                                }
                            }
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

                // Call handler.
                let response_payload = handler.handle(&envelope.from, &payload).await;

                // Send response.
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
            let state = handshake_states.remove(peer_key).unwrap();
            let hs = match state {
                PeerNoise::Handshaking(h) => *h,
                _ => unreachable!(),
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
                let json = serde_json::to_string(&reply).unwrap();
                let mut s = sink.lock().await;
                let _ = s.send(Message::text(json)).await;
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

async fn receive_ws_json<T: serde::de::DeserializeOwned>(
    stream: &mut futures_util::stream::SplitStream<WsStream>,
) -> Option<T> {
    match stream.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}
