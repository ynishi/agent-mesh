use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use agent_mesh_core::identity::{AgentId, AgentKeypair, MessageId};
use agent_mesh_core::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use tokio_tungstenite_wasm::Message;

use crate::error::WasmSdkError;

type SessionMap = HashMap<String, NoiseTransport>;
type WsSink = futures_util::stream::SplitSink<tokio_tungstenite_wasm::WebSocketStream, Message>;
type WsStreamHalf = futures_util::stream::SplitStream<tokio_tungstenite_wasm::WebSocketStream>;

/// Minimal cross-platform mesh client for PoC.
///
/// Uses `Rc<RefCell<>>` — designed for single-threaded WASM runtime.
/// Not `Send`/`Sync`; this is intentional for browser environment.
pub struct WasmMeshClient {
    keypair: AgentKeypair,
    noise_keypair: NoiseKeypair,
    sink: Rc<RefCell<WsSink>>,
    stream: Rc<RefCell<WsStreamHalf>>,
    sessions: Rc<RefCell<SessionMap>>,
}

impl WasmMeshClient {
    /// Connect to the relay and authenticate.
    pub async fn connect(keypair: AgentKeypair, relay_url: &str) -> Result<Self, WasmSdkError> {
        let ws_stream = tokio_tungstenite_wasm::connect(relay_url)
            .await
            .map_err(|e| WasmSdkError::Connection(e.to_string()))?;

        let (mut sink, mut stream) = ws_stream.split();

        let _session_token = challenge_response_auth(&keypair, &mut sink, &mut stream).await?;

        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| WasmSdkError::Protocol(e.to_string()))?;

        Ok(Self {
            keypair,
            noise_keypair,
            sink: Rc::new(RefCell::new(sink)),
            stream: Rc::new(RefCell::new(stream)),
            sessions: Rc::new(RefCell::new(HashMap::new())),
        })
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> AgentId {
        self.keypair.agent_id()
    }

    /// Perform Noise_XX handshake with target if no session exists.
    pub async fn ensure_session(&mut self, target: &AgentId) -> Result<(), WasmSdkError> {
        if self.sessions.borrow().contains_key(target.as_str()) {
            return Ok(());
        }

        let mut handshake = NoiseHandshake::new_initiator(&self.noise_keypair)
            .map_err(|e| WasmSdkError::Protocol(format!("noise init: {e}")))?;

        // XX message 1: -> e
        let hs_data1 = handshake
            .write_message()
            .map_err(|e| WasmSdkError::Protocol(format!("noise write msg1: {e}")))?;
        let msg1 = MeshEnvelope::new_signed(
            &self.keypair,
            target.clone(),
            MessageType::Handshake,
            serde_json::Value::String(hs_data1),
        )
        .map_err(|e| WasmSdkError::Protocol(e.to_string()))?;
        let msg1_id = msg1.id;

        self.send_envelope(&msg1).await?;
        let msg2 = self.receive_envelope_matching(msg1_id).await?;

        // XX message 2: <- e, ee, s, es
        let hs_data2 = msg2
            .payload
            .as_str()
            .ok_or_else(|| WasmSdkError::Protocol("handshake msg2 payload not a string".into()))?;
        handshake
            .read_message(hs_data2)
            .map_err(|e| WasmSdkError::Protocol(format!("noise read msg2: {e}")))?;

        // XX message 3: -> s, se
        let hs_data3 = handshake
            .write_message()
            .map_err(|e| WasmSdkError::Protocol(format!("noise write msg3: {e}")))?;
        let msg3 = MeshEnvelope::new_signed_reply(
            &self.keypair,
            target.clone(),
            MessageType::Handshake,
            Some(msg2.id),
            serde_json::Value::String(hs_data3),
        )
        .map_err(|e| WasmSdkError::Protocol(e.to_string()))?;

        self.send_envelope(&msg3).await?;

        let transport = handshake
            .into_transport()
            .map_err(|e| WasmSdkError::Protocol(format!("noise transport: {e}")))?;
        self.sessions
            .borrow_mut()
            .insert(target.as_str().to_string(), transport);

        Ok(())
    }

    /// Send an encrypted request to a remote agent and wait for the response.
    pub async fn request(
        &mut self,
        target: &AgentId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, WasmSdkError> {
        self.ensure_session(target).await?;

        let plaintext =
            serde_json::to_vec(&payload).map_err(|e| WasmSdkError::Protocol(e.to_string()))?;
        let ciphertext_b64 = {
            let mut sessions = self.sessions.borrow_mut();
            let transport = sessions.get_mut(target.as_str()).ok_or_else(|| {
                WasmSdkError::Protocol("noise session missing after handshake".into())
            })?;
            transport
                .encrypt(&plaintext)
                .map_err(|e| WasmSdkError::Protocol(format!("encrypt: {e}")))?
        };

        let envelope = MeshEnvelope::new_encrypted(
            &self.keypair,
            target.clone(),
            MessageType::Request,
            None,
            serde_json::Value::String(ciphertext_b64),
        )
        .map_err(|e| WasmSdkError::Protocol(e.to_string()))?;

        let msg_id = envelope.id;
        self.send_envelope(&envelope).await?;
        let response = self.receive_envelope_matching(msg_id).await?;

        if response.msg_type == MessageType::Error {
            return Err(WasmSdkError::Remote(response.payload.to_string()));
        }

        if response.encrypted {
            let ct = response
                .payload
                .as_str()
                .ok_or_else(|| WasmSdkError::Protocol("encrypted payload not a string".into()))?;
            let mut sessions = self.sessions.borrow_mut();
            let transport = sessions
                .get_mut(target.as_str())
                .ok_or_else(|| WasmSdkError::Protocol("no noise session for decrypt".into()))?;
            let pt = transport
                .decrypt(ct)
                .map_err(|e| WasmSdkError::Protocol(format!("decrypt: {e}")))?;
            serde_json::from_slice(&pt).map_err(|e| WasmSdkError::Protocol(e.to_string()))
        } else {
            Ok(response.payload)
        }
    }

    // -- Internal helpers --

    async fn send_envelope(&self, envelope: &MeshEnvelope) -> Result<(), WasmSdkError> {
        let json =
            serde_json::to_string(envelope).map_err(|e| WasmSdkError::Protocol(e.to_string()))?;
        self.sink
            .borrow_mut()
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| WasmSdkError::Send(e.to_string()))
    }

    async fn receive_envelope_matching(
        &self,
        expected_reply_to: MessageId,
    ) -> Result<MeshEnvelope, WasmSdkError> {
        loop {
            let msg = self.stream.borrow_mut().next().await;
            match msg {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(envelope) = serde_json::from_str::<MeshEnvelope>(&text) {
                        if envelope.in_reply_to == Some(expected_reply_to) {
                            return Ok(envelope);
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(WasmSdkError::Receive(e.to_string()));
                }
                None => {
                    return Err(WasmSdkError::Receive("connection closed".into()));
                }
                _ => {}
            }
        }
    }
}

// -- Auth helpers --

async fn challenge_response_auth(
    keypair: &AgentKeypair,
    sink: &mut WsSink,
    stream: &mut WsStreamHalf,
) -> Result<Option<String>, WasmSdkError> {
    // Step 1: Send AuthHello.
    let hello = AuthHello {
        agent_id: keypair.agent_id(),
    };
    let json = serde_json::to_string(&hello).map_err(|e| WasmSdkError::Protocol(e.to_string()))?;
    sink.send(Message::Text(json.into()))
        .await
        .map_err(|e| WasmSdkError::Auth(e.to_string()))?;

    // Step 2: Receive AuthChallenge.
    let challenge: AuthChallenge = receive_ws_json(stream)
        .await
        .ok_or_else(|| WasmSdkError::Auth("no challenge received".into()))?;

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
        serde_json::to_string(&response).map_err(|e| WasmSdkError::Protocol(e.to_string()))?;
    sink.send(Message::Text(json.into()))
        .await
        .map_err(|e| WasmSdkError::Auth(e.to_string()))?;

    // Step 4: Receive AuthResult.
    let result: AuthResult = receive_ws_json(stream)
        .await
        .ok_or_else(|| WasmSdkError::Auth("no auth result received".into()))?;
    if !result.success {
        return Err(WasmSdkError::Auth(
            result.error.unwrap_or_else(|| "auth failed".into()),
        ));
    }

    Ok(result.session_token)
}

async fn receive_ws_json<T: serde::de::DeserializeOwned>(stream: &mut WsStreamHalf) -> Option<T> {
    match stream.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}
