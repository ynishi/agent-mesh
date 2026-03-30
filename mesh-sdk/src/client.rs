use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use mesh_proto::identity::{AgentId, AgentKeypair};
use mesh_proto::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use mesh_proto::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::error::SdkError;

type PendingMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<MeshEnvelope>>>>;
type SessionMap = Arc<Mutex<HashMap<String, NoiseTransport>>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;

/// Mesh client for sending requests to remote agents through the relay.
/// Automatically negotiates Noise_XX E2E encryption on first request to each target.
pub struct MeshClient {
    keypair: Arc<AgentKeypair>,
    noise_keypair: Arc<NoiseKeypair>,
    relay_url: String,
    pending: PendingMap,
    sink: Arc<Mutex<WsSink>>,
    sessions: SessionMap,
}

impl MeshClient {
    /// Connect to the relay and authenticate.
    pub async fn connect(keypair: AgentKeypair, relay_url: &str) -> Result<Self, SdkError> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|e| SdkError::Connection(e.to_string()))?;

        let (mut sink, mut stream) = ws_stream.split();

        // Challenge-Response auth.
        // Step 1: Send AuthHello.
        let hello = AuthHello {
            agent_id: keypair.agent_id(),
        };
        let json = serde_json::to_string(&hello).map_err(|e| SdkError::Protocol(e.to_string()))?;
        sink.send(Message::text(json))
            .await
            .map_err(|e| SdkError::Auth(e.to_string()))?;

        // Step 2: Receive AuthChallenge.
        let challenge: AuthChallenge = receive_ws_json(&mut stream)
            .await
            .ok_or_else(|| SdkError::Auth("no challenge received".into()))?;

        // Step 3: Sign nonce and send AuthResponse.
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

        // Step 4: Receive AuthResult.
        let result: AuthResult = receive_ws_json(&mut stream)
            .await
            .ok_or_else(|| SdkError::Auth("no auth result received".into()))?;
        if !result.success {
            return Err(SdkError::Auth(
                result.error.unwrap_or_else(|| "auth failed".into()),
            ));
        }

        // Generate Noise keypair for E2E encryption.
        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| SdkError::Protocol(e.to_string()))?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::new(Mutex::new(sink));
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

        // Spawn reader task.
        let pending_clone = Arc::clone(&pending);
        tokio::spawn(reader_loop(stream, pending_clone));

        Ok(Self {
            keypair: Arc::new(keypair),
            noise_keypair: Arc::new(noise_keypair),
            relay_url: relay_url.to_string(),
            pending,
            sink,
            sessions,
        })
    }

    /// Send an encrypted request to a remote agent and wait for the response.
    ///
    /// Automatically performs Noise_XX handshake on first request to each target.
    pub async fn request(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, SdkError> {
        // Ensure Noise session exists with target.
        self.ensure_session(target, timeout).await?;

        // Encrypt payload.
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
            // Error responses may be unencrypted (e.g. ACL denial before decryption).
            if response.encrypted {
                let decrypted = self.decrypt_payload(target, &response.payload).await?;
                return Err(SdkError::Remote(
                    String::from_utf8_lossy(&decrypted).to_string(),
                ));
            }
            return Err(SdkError::Remote(response.payload.to_string()));
        }

        // Decrypt response payload.
        if response.encrypted {
            let decrypted = self.decrypt_payload(target, &response.payload).await?;
            serde_json::from_slice(&decrypted).map_err(|e| SdkError::Protocol(e.to_string()))
        } else {
            Ok(response.payload)
        }
    }

    /// Send a plaintext request (no encryption). For backward compatibility.
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

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Perform Noise_XX handshake with target if no session exists.
    async fn ensure_session(&self, target: &AgentId, timeout: Duration) -> Result<(), SdkError> {
        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(target.as_str()) {
                return Ok(());
            }
        }

        let mut handshake = NoiseHandshake::new_initiator(&self.noise_keypair)
            .map_err(|e| SdkError::Protocol(format!("noise init: {e}")))?;

        // XX message 1: -> e
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

        // XX message 2: <- e, ee, s, es
        let hs_data2 = msg2
            .payload
            .as_str()
            .ok_or_else(|| SdkError::Protocol("handshake msg2 payload not a string".into()))?;
        handshake
            .read_message(hs_data2)
            .map_err(|e| SdkError::Protocol(format!("noise read msg2: {e}")))?;

        // XX message 3: -> s, se
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

        // Send msg3 (no response expected).
        let json = serde_json::to_string(&msg3).map_err(|e| SdkError::Protocol(e.to_string()))?;
        {
            let mut sink = self.sink.lock().await;
            sink.send(Message::text(json))
                .await
                .map_err(|e| SdkError::Send(e.to_string()))?;
        }

        // Transition to transport mode.
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

    /// Send an envelope and wait for the response matched by in_reply_to.
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

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn receive_ws_json<T: serde::de::DeserializeOwned>(
    stream: &mut futures_util::stream::SplitStream<WsStream>,
) -> Option<T> {
    match stream.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

async fn reader_loop(mut stream: futures_util::stream::SplitStream<WsStream>, pending: PendingMap) {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(envelope) = serde_json::from_str::<MeshEnvelope>(&text) {
                    if let Some(reply_to) = envelope.in_reply_to {
                        let mut pending = pending.lock().await;
                        if let Some(tx) = pending.remove(&reply_to) {
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
