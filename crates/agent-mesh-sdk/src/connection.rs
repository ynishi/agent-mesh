use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::identity::MessageId;
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use agent_mesh_core::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, AuthResume, MeshEnvelope, MessageType,
};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;

use crate::error::SdkError;

// --- StreamReceiver (public API) ---

/// Receiver for a streaming response. Yields chunks until the stream ends.
pub struct StreamReceiver {
    rx: mpsc::UnboundedReceiver<Result<serde_json::Value, SdkError>>,
    cancel_tx: Option<oneshot::Sender<()>>,
}

impl StreamReceiver {
    pub(crate) fn new(
        rx: mpsc::UnboundedReceiver<Result<serde_json::Value, SdkError>>,
        cancel_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            rx,
            cancel_tx: Some(cancel_tx),
        }
    }

    /// Receive the next chunk. Returns None when the stream ends.
    pub async fn next(&mut self) -> Option<Result<serde_json::Value, SdkError>> {
        self.rx.recv().await
    }

    /// Collect all chunks into a Vec.
    pub async fn collect(mut self) -> Result<Vec<serde_json::Value>, SdkError> {
        let mut chunks = Vec::new();
        while let Some(result) = self.rx.recv().await {
            chunks.push(result?);
        }
        Ok(chunks)
    }

    /// Cancel the stream. Sends a Cancel message to the remote agent.
    pub fn cancel(mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

// --- Shared type aliases ---

pub(crate) type PendingMap = Arc<Mutex<HashMap<MessageId, oneshot::Sender<MeshEnvelope>>>>;
pub(crate) type StreamPendingMap =
    Arc<Mutex<HashMap<MessageId, mpsc::UnboundedSender<Result<serde_json::Value, SdkError>>>>>;
pub(crate) type SessionMap = Arc<Mutex<HashMap<String, NoiseTransport>>>;
pub(crate) type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
pub(crate) type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

// --- Common connection state ---

/// Shared connection state for both MeshClient and MeshAgent.
///
/// Holds the keypair, Noise keypair, pending request maps, WebSocket sink,
/// and Noise session cache. All send-side operations (request, handshake,
/// cancel, decrypt) are implemented here.
pub(crate) struct MeshConnection {
    pub(crate) keypair: Arc<AgentKeypair>,
    pub(crate) noise_keypair: Arc<NoiseKeypair>,
    pub(crate) pending: PendingMap,
    pub(crate) stream_pending: StreamPendingMap,
    pub(crate) sink: Arc<Mutex<WsSink>>,
    pub(crate) sessions: SessionMap,
}

impl MeshConnection {
    pub fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
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

    /// Send an encrypted request and receive a streaming response.
    pub async fn request_stream(
        &self,
        target: &AgentId,
        payload: serde_json::Value,
        timeout: Duration,
    ) -> Result<StreamReceiver, SdkError> {
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
            MessageType::StreamRequest,
            None,
            serde_json::Value::String(ciphertext_b64),
        )
        .map_err(|e| SdkError::Protocol(e.to_string()))?;

        let msg_id = envelope.id;
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut sp = self.stream_pending.lock().await;
            sp.insert(msg_id, tx);
        }

        let json =
            serde_json::to_string(&envelope).map_err(|e| SdkError::Protocol(e.to_string()))?;
        {
            let mut sink = self.sink.lock().await;
            sink.send(Message::text(json))
                .await
                .map_err(|e| SdkError::Send(e.to_string()))?;
        }

        // Set up cancel: when cancel_tx fires, send Cancel envelope.
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        {
            let keypair = Arc::clone(&self.keypair);
            let sink = Arc::clone(&self.sink);
            let target = target.clone();
            tokio::spawn(async move {
                if cancel_rx.await.is_ok() {
                    let cancel = MeshEnvelope::new_signed_reply(
                        &keypair,
                        target,
                        MessageType::Cancel,
                        Some(msg_id),
                        serde_json::Value::Null,
                    );
                    if let Ok(cancel) = cancel {
                        if let Ok(json) = serde_json::to_string(&cancel) {
                            let mut s = sink.lock().await;
                            let _ = s.send(Message::text(json)).await;
                        }
                    }
                }
            });
        }

        Ok(StreamReceiver::new(rx, cancel_tx))
    }

    /// Perform Noise_XX handshake with target if no session exists.
    pub(crate) async fn ensure_session(
        &self,
        target: &AgentId,
        timeout: Duration,
    ) -> Result<(), SdkError> {
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
    /// On timeout, sends a Cancel message to the target.
    pub(crate) async fn send_and_wait(
        &self,
        envelope: MeshEnvelope,
        msg_id: MessageId,
        timeout: Duration,
    ) -> Result<MeshEnvelope, SdkError> {
        let target = envelope.to.clone();
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
                self.send_cancel(&target, msg_id).await;
                Err(SdkError::Timeout)
            }
        }
    }

    /// Send a Cancel message for a given request ID.
    async fn send_cancel(&self, target: &AgentId, request_id: MessageId) {
        let cancel = MeshEnvelope::new_signed_reply(
            &self.keypair,
            target.clone(),
            MessageType::Cancel,
            Some(request_id),
            serde_json::Value::Null,
        );
        if let Ok(cancel) = cancel {
            if let Ok(json) = serde_json::to_string(&cancel) {
                let mut sink = self.sink.lock().await;
                let _ = sink.send(Message::text(json)).await;
            }
        }
    }

    /// Decrypt an encrypted payload using the Noise session for the target.
    pub(crate) async fn decrypt_payload(
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

// --- Common free-standing functions ---

/// Challenge-response authentication over a WebSocket.
///
/// Performs the 4-step auth handshake (AuthHello → AuthChallenge → AuthResponse → AuthResult)
/// and returns the session token on success.
pub(crate) async fn challenge_response_auth(
    keypair: &AgentKeypair,
    sink: &mut futures_util::stream::SplitSink<WsStream, Message>,
    stream: &mut futures_util::stream::SplitStream<WsStream>,
) -> Result<Option<String>, SdkError> {
    // Step 1: Send AuthHello.
    let hello = AuthHello {
        agent_id: keypair.agent_id(),
    };
    let json = serde_json::to_string(&hello).map_err(|e| SdkError::Protocol(e.to_string()))?;
    sink.send(Message::text(json))
        .await
        .map_err(|e| SdkError::Auth(e.to_string()))?;

    // Step 2: Receive AuthChallenge.
    let challenge: AuthChallenge = receive_ws_json(stream)
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
    let json = serde_json::to_string(&response).map_err(|e| SdkError::Protocol(e.to_string()))?;
    sink.send(Message::text(json))
        .await
        .map_err(|e| SdkError::Auth(e.to_string()))?;

    // Step 4: Receive AuthResult.
    let result: AuthResult = receive_ws_json(stream)
        .await
        .ok_or_else(|| SdkError::Auth("no auth result received".into()))?;
    if !result.success {
        return Err(SdkError::Auth(
            result.error.unwrap_or_else(|| "auth failed".into()),
        ));
    }

    Ok(result.session_token)
}

/// Attempt to resume a session using a stored token.
///
/// Returns (new_stream, new_sink, new_token) on success.
pub(crate) async fn attempt_resume(
    keypair: &AgentKeypair,
    relay_url: &str,
    token: &str,
) -> Result<
    (
        futures_util::stream::SplitStream<WsStream>,
        futures_util::stream::SplitSink<WsStream, Message>,
        String,
    ),
    SdkError,
> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| SdkError::Connection(e.to_string()))?;

    let (mut sink, mut stream) = ws_stream.split();

    let resume = AuthResume {
        agent_id: keypair.agent_id(),
        session_token: token.to_string(),
    };
    let json = serde_json::to_string(&resume).map_err(|e| SdkError::Protocol(e.to_string()))?;
    sink.send(Message::text(json))
        .await
        .map_err(|e| SdkError::Auth(e.to_string()))?;

    let result: AuthResult = receive_ws_json(&mut stream)
        .await
        .ok_or_else(|| SdkError::Auth("no auth result on resume".into()))?;

    if !result.success {
        return Err(SdkError::Auth(
            result.error.unwrap_or_else(|| "resume failed".into()),
        ));
    }

    let new_token = result.session_token.unwrap_or_default();
    Ok((stream, sink, new_token))
}

/// Receive a JSON-deserialized message from a WebSocket stream.
pub(crate) async fn receive_ws_json<T: serde::de::DeserializeOwned>(
    stream: &mut futures_util::stream::SplitStream<WsStream>,
) -> Option<T> {
    match stream.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

/// Decrypt an envelope's payload using the Noise session for the sender.
pub(crate) async fn decrypt_envelope_payload(
    envelope: &MeshEnvelope,
    sessions: &SessionMap,
) -> Result<serde_json::Value, SdkError> {
    let ct = envelope
        .payload
        .as_str()
        .ok_or_else(|| SdkError::Protocol("encrypted payload not a string".into()))?;
    let mut sess = sessions.lock().await;
    let transport = sess
        .get_mut(envelope.from.as_str())
        .ok_or_else(|| SdkError::Protocol("no noise session for decrypt".into()))?;
    let pt = transport
        .decrypt(ct)
        .map_err(|e| SdkError::Protocol(format!("decrypt: {e}")))?;
    serde_json::from_slice(&pt).map_err(|e| SdkError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stream_receiver_receives_chunks() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut receiver = StreamReceiver::new(rx, cancel_tx);

        tx.send(Ok(serde_json::json!({"chunk": 1}))).unwrap();
        tx.send(Ok(serde_json::json!({"chunk": 2}))).unwrap();
        drop(tx); // Close channel

        let chunk1 = receiver.next().await.unwrap().unwrap();
        assert_eq!(chunk1, serde_json::json!({"chunk": 1}));

        let chunk2 = receiver.next().await.unwrap().unwrap();
        assert_eq!(chunk2, serde_json::json!({"chunk": 2}));

        // Channel closed
        assert!(receiver.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_receiver_collect() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let receiver = StreamReceiver::new(rx, cancel_tx);

        tx.send(Ok(serde_json::json!("a"))).unwrap();
        tx.send(Ok(serde_json::json!("b"))).unwrap();
        tx.send(Ok(serde_json::json!("c"))).unwrap();
        drop(tx);

        let chunks = receiver.collect().await.unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], serde_json::json!("a"));
    }

    #[tokio::test]
    async fn stream_receiver_collect_propagates_error() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let receiver = StreamReceiver::new(rx, cancel_tx);

        tx.send(Ok(serde_json::json!("ok"))).unwrap();
        tx.send(Err(SdkError::Remote("test error".into()))).unwrap();
        drop(tx);

        let result = receiver.collect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stream_receiver_cancel_sends_signal() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let receiver = StreamReceiver::new(rx, cancel_tx);

        drop(tx);
        receiver.cancel();

        // cancel_rx should have received the signal
        assert!(cancel_rx.await.is_ok());
    }
}
