use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::AgentId;

/// Envelope for all messages passing through the mesh relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    /// Unique message ID.
    pub id: Uuid,
    /// Sender agent.
    pub from: AgentId,
    /// Destination agent.
    pub to: AgentId,
    /// Message type tag.
    pub msg_type: MessageType,
    /// For Response/Error: the original request's envelope ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<Uuid>,
    /// The payload (opaque JSON).
    /// When `encrypted` is true, this contains a JSON string with
    /// base64url-encoded Noise ciphertext.
    pub payload: serde_json::Value,
    /// Whether the payload is Noise-encrypted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub encrypted: bool,
    /// Ed25519 signature over the canonical form.
    /// Base64url-encoded.
    pub signature: String,
    /// Timestamp (Unix millis).
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Invoke a capability on the target agent.
    Request,
    /// Response to a request.
    Response,
    /// Error response.
    Error,
    /// Relay control messages (auth handshake, ping, etc.).
    Control,
    /// Noise Protocol handshake message (E2E encryption setup).
    Handshake,
}

/// The part of the envelope that gets signed.
#[derive(Serialize)]
struct SignedPortion<'a> {
    id: &'a Uuid,
    from: &'a AgentId,
    to: &'a AgentId,
    msg_type: &'a MessageType,
    in_reply_to: &'a Option<Uuid>,
    payload: &'a serde_json::Value,
    encrypted: bool,
    timestamp: i64,
}

impl MeshEnvelope {
    /// Create and sign an envelope (plaintext).
    pub fn new_signed(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        payload: serde_json::Value,
    ) -> Result<Self, crate::error::ProtoError> {
        Self::build(from_keypair, to, msg_type, None, payload, false)
    }

    /// Create and sign a reply envelope (with in_reply_to, plaintext).
    pub fn new_signed_reply(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        in_reply_to: Option<Uuid>,
        payload: serde_json::Value,
    ) -> Result<Self, crate::error::ProtoError> {
        Self::build(from_keypair, to, msg_type, in_reply_to, payload, false)
    }

    /// Create and sign an encrypted envelope.
    pub fn new_encrypted(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        in_reply_to: Option<Uuid>,
        payload: serde_json::Value,
    ) -> Result<Self, crate::error::ProtoError> {
        Self::build(from_keypair, to, msg_type, in_reply_to, payload, true)
    }

    fn build(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        in_reply_to: Option<Uuid>,
        payload: serde_json::Value,
        encrypted: bool,
    ) -> Result<Self, crate::error::ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let id = Uuid::new_v4();
        let from = from_keypair.agent_id();
        let timestamp = chrono::Utc::now().timestamp_millis();

        let signed = SignedPortion {
            id: &id,
            from: &from,
            to: &to,
            msg_type: &msg_type,
            in_reply_to: &in_reply_to,
            payload: &payload,
            encrypted,
            timestamp,
        };
        let canonical = serde_json::to_vec(&signed)?;
        let sig = from_keypair.sign(&canonical);
        let signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(Self {
            id,
            from,
            to,
            msg_type,
            in_reply_to,
            payload,
            encrypted,
            signature,
            timestamp,
        })
    }

    /// Verify the envelope signature.
    pub fn verify(&self) -> Result<(), crate::error::ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use ed25519_dalek::Signature;

        let signed = SignedPortion {
            id: &self.id,
            from: &self.from,
            to: &self.to,
            msg_type: &self.msg_type,
            in_reply_to: &self.in_reply_to,
            payload: &self.payload,
            encrypted: self.encrypted,
            timestamp: self.timestamp,
        };
        let canonical = serde_json::to_vec(&signed)?;

        let sig_bytes = URL_SAFE_NO_PAD.decode(&self.signature).map_err(|e| {
            crate::error::ProtoError::InvalidMessage(format!("bad sig base64: {e}"))
        })?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            crate::error::ProtoError::InvalidMessage("signature must be 64 bytes".into())
        })?;
        let signature = Signature::from_bytes(&sig_arr);

        crate::identity::verify_signature(&self.from, &canonical, &signature)
    }
}

/// Step 1: Agent → Relay. Declares identity, requests a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHello {
    pub agent_id: AgentId,
}

/// Step 2: Relay → Agent. Sends a random nonce to be signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
}

/// Step 3: Agent → Relay. Returns the signed nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub agent_id: AgentId,
    /// Ed25519 signature over the nonce bytes, base64url-encoded.
    pub signature: String,
}

/// Step 4: Relay → Agent. Auth outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// --- Backward compat alias (will be removed in v0.3) ---

/// Legacy handshake type. Deprecated: use AuthHello + AuthResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHandshake {
    pub agent_id: AgentId,
    pub signature: String,
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;

    #[test]
    fn envelope_sign_verify() {
        let sender = AgentKeypair::generate();
        let receiver = AgentKeypair::generate();

        let env = MeshEnvelope::new_signed(
            &sender,
            receiver.agent_id(),
            MessageType::Request,
            serde_json::json!({"capability": "scheduling", "action": "list"}),
        )
        .unwrap();

        assert!(env.verify().is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let sender = AgentKeypair::generate();
        let receiver = AgentKeypair::generate();

        let mut env = MeshEnvelope::new_signed(
            &sender,
            receiver.agent_id(),
            MessageType::Request,
            serde_json::json!({"capability": "scheduling"}),
        )
        .unwrap();

        env.payload = serde_json::json!({"capability": "admin"});
        assert!(env.verify().is_err());
    }
}
