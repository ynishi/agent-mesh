use serde::{Deserialize, Serialize};

use crate::identity::{AgentCardId, AgentId, MessageId};

/// Envelope for all messages passing through the mesh relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelope {
    /// Unique message ID.
    pub id: MessageId,
    /// Sender agent.
    pub from: AgentId,
    /// Destination agent.
    pub to: AgentId,
    /// Message type tag.
    pub msg_type: MessageType,
    /// For Response/Error: the original request's envelope ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<MessageId>,
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
    /// Request that expects a streaming response (multiple StreamChunk + StreamEnd).
    StreamRequest,
    /// One chunk of a streaming response. `in_reply_to` ties it to the original request.
    StreamChunk,
    /// Signals the end of a streaming response.
    StreamEnd,
    /// Cancel a pending request or stream. `in_reply_to` identifies the target request.
    Cancel,
}

/// The part of the envelope that gets signed.
#[derive(Serialize)]
struct SignedPortion<'a> {
    id: &'a MessageId,
    from: &'a AgentId,
    to: &'a AgentId,
    msg_type: &'a MessageType,
    in_reply_to: &'a Option<MessageId>,
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
        in_reply_to: Option<MessageId>,
        payload: serde_json::Value,
    ) -> Result<Self, crate::error::ProtoError> {
        Self::build(from_keypair, to, msg_type, in_reply_to, payload, false)
    }

    /// Create and sign an encrypted envelope.
    pub fn new_encrypted(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        in_reply_to: Option<MessageId>,
        payload: serde_json::Value,
    ) -> Result<Self, crate::error::ProtoError> {
        Self::build(from_keypair, to, msg_type, in_reply_to, payload, true)
    }

    fn build(
        from_keypair: &crate::identity::AgentKeypair,
        to: AgentId,
        msg_type: MessageType,
        in_reply_to: Option<MessageId>,
        payload: serde_json::Value,
        encrypted: bool,
    ) -> Result<Self, crate::error::ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let id = MessageId::new_v4();
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
    /// Session token for connection resumption (issued on successful auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Resume a previously authenticated session without full challenge-response.
/// Sent instead of AuthHello when the agent has a valid session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResume {
    pub agent_id: AgentId,
    /// The session token received from a previous AuthResult.
    pub session_token: String,
}

/// A signed key revocation declaration.
///
/// An agent can revoke its own key by signing a revocation message.
/// Once revoked, the relay rejects authentication and message routing
/// for the revoked agent ID.
///
/// The signature covers the canonical form: `{agent_id}:REVOKE:{timestamp}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRevocation {
    /// The agent ID being revoked (must match the signer).
    pub agent_id: AgentId,
    /// Optional human-readable reason for revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix timestamp (millis) when the revocation was issued.
    pub timestamp: i64,
    /// Ed25519 signature over `"{agent_id}:REVOKE:{timestamp}"`, base64url-encoded.
    pub signature: String,
}

impl KeyRevocation {
    /// Create a signed revocation for the given keypair.
    pub fn new(keypair: &crate::identity::AgentKeypair, reason: Option<String>) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let agent_id = keypair.agent_id();
        let timestamp = chrono::Utc::now().timestamp_millis();
        let canonical = Self::canonical_bytes(&agent_id, timestamp);
        let sig = keypair.sign(&canonical);
        let signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Self {
            agent_id,
            reason,
            timestamp,
            signature,
        }
    }

    /// Verify that this revocation was signed by the agent being revoked.
    pub fn verify(&self) -> Result<(), crate::error::ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use ed25519_dalek::Signature;

        let canonical = Self::canonical_bytes(&self.agent_id, self.timestamp);

        let sig_bytes = URL_SAFE_NO_PAD.decode(&self.signature).map_err(|e| {
            crate::error::ProtoError::InvalidMessage(format!("bad revocation sig base64: {e}"))
        })?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            crate::error::ProtoError::InvalidMessage("revocation signature must be 64 bytes".into())
        })?;
        let signature = Signature::from_bytes(&sig_arr);

        crate::identity::verify_signature(&self.agent_id, &canonical, &signature)
    }

    fn canonical_bytes(agent_id: &AgentId, timestamp: i64) -> Vec<u8> {
        format!("{}:REVOKE:{}", agent_id.as_str(), timestamp).into_bytes()
    }
}

/// Request to rotate an agent's Ed25519 key.
///
/// The current key owner initiates rotation by providing the new agent ID
/// and a cryptographic proof (signed with the current key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    /// The AgentCard ID (UUID) identifying the agent.
    pub card_id: AgentCardId,
    /// The new agent ID (derived from the new public key).
    pub new_agent_id: AgentId,
    /// Proof that the requester owns the current key.
    pub proof: KeyRotationProof,
    /// Grace period in seconds (both keys valid during this window).
    /// Default: 86400 (24h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period_secs: Option<u64>,
}

/// Cryptographic proof of ownership for key rotation.
///
/// The current (old) key signs a canonical rotation message:
/// `"{old_agent_id}:ROTATE_TO:{new_agent_id}:{timestamp}"`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationProof {
    /// The current agent ID (signer).
    pub old_agent_id: AgentId,
    /// Ed25519 signature over `"{old_agent_id}:ROTATE_TO:{new_agent_id}:{timestamp}"`,
    /// base64url-encoded.
    pub signature: String,
    /// Timestamp (Unix millis) when the proof was created.
    pub timestamp: i64,
}

impl KeyRotationProof {
    /// Create a proof signed by `keypair` that authorises rotation to `new_agent_id`.
    pub fn new(keypair: &crate::identity::AgentKeypair, new_agent_id: &AgentId) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let old_agent_id = keypair.agent_id();
        let timestamp = chrono::Utc::now().timestamp_millis();
        let canonical = Self::canonical_bytes(&old_agent_id, new_agent_id, timestamp);
        let sig = keypair.sign(&canonical);
        let signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Self {
            old_agent_id,
            signature,
            timestamp,
        }
    }

    /// Verify that this proof was signed by the agent identified by `old_agent_id`.
    pub fn verify(&self, new_agent_id: &AgentId) -> Result<(), crate::error::ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use ed25519_dalek::Signature;

        let canonical = Self::canonical_bytes(&self.old_agent_id, new_agent_id, self.timestamp);

        let sig_bytes = URL_SAFE_NO_PAD.decode(&self.signature).map_err(|e| {
            crate::error::ProtoError::InvalidMessage(format!("bad rotation proof sig base64: {e}"))
        })?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            crate::error::ProtoError::InvalidMessage(
                "rotation proof signature must be 64 bytes".into(),
            )
        })?;
        let signature = Signature::from_bytes(&sig_arr);

        crate::identity::verify_signature(&self.old_agent_id, &canonical, &signature)
    }

    fn canonical_bytes(old_agent_id: &AgentId, new_agent_id: &AgentId, timestamp: i64) -> Vec<u8> {
        format!(
            "{}:ROTATE_TO:{}:{}",
            old_agent_id.as_str(),
            new_agent_id.as_str(),
            timestamp
        )
        .into_bytes()
    }
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

    #[test]
    fn key_revocation_sign_verify() {
        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, Some("compromised".into()));

        assert_eq!(rev.agent_id, kp.agent_id());
        assert_eq!(rev.reason.as_deref(), Some("compromised"));
        assert!(rev.verify().is_ok());
    }

    #[test]
    fn key_revocation_tampered_timestamp_fails() {
        let kp = AgentKeypair::generate();
        let mut rev = KeyRevocation::new(&kp, None);
        rev.timestamp += 1;
        assert!(rev.verify().is_err());
    }

    #[test]
    fn key_revocation_wrong_agent_fails() {
        let kp = AgentKeypair::generate();
        let other = AgentKeypair::generate();
        let mut rev = KeyRevocation::new(&kp, None);
        // Replace agent_id with a different agent — signature won't match.
        rev.agent_id = other.agent_id();
        assert!(rev.verify().is_err());
    }

    #[test]
    fn key_revocation_serialization_roundtrip() {
        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, Some("key rotation".into()));
        let json = serde_json::to_string(&rev).unwrap();
        let deserialized: KeyRevocation = serde_json::from_str(&json).unwrap();
        assert!(deserialized.verify().is_ok());
        assert_eq!(deserialized.agent_id, rev.agent_id);
    }

    // ── KeyRotationProof tests ───────────────────────────────────────────────

    #[test]
    fn key_rotation_proof_sign_verify() {
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        assert_eq!(proof.old_agent_id, old_kp.agent_id());
        assert!(proof.verify(&new_kp.agent_id()).is_ok());
    }

    #[test]
    fn key_rotation_proof_wrong_new_agent_fails() {
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let other_kp = AgentKeypair::generate();
        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        // Verify with a different new_agent_id — canonical bytes differ.
        assert!(proof.verify(&other_kp.agent_id()).is_err());
    }

    #[test]
    fn key_rotation_proof_tampered_timestamp_fails() {
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let mut proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        proof.timestamp += 1;
        assert!(proof.verify(&new_kp.agent_id()).is_err());
    }

    #[test]
    fn key_rotation_proof_wrong_old_agent_fails() {
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let other_kp = AgentKeypair::generate();
        let mut proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        // Swap old_agent_id to a different identity — verify_signature will reject.
        proof.old_agent_id = other_kp.agent_id();
        assert!(proof.verify(&new_kp.agent_id()).is_err());
    }

    #[test]
    fn key_rotation_proof_serialization_roundtrip() {
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        let json = serde_json::to_string(&proof).unwrap();
        let de: KeyRotationProof = serde_json::from_str(&json).unwrap();
        assert!(de.verify(&new_kp.agent_id()).is_ok());
        assert_eq!(de.old_agent_id, proof.old_agent_id);
    }

    #[test]
    fn key_rotation_request_serialization_roundtrip() {
        use crate::identity::AgentCardId;
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let card_id = AgentCardId::new_v4();
        let proof = KeyRotationProof::new(&old_kp, &new_kp.agent_id());
        let req = KeyRotationRequest {
            card_id,
            new_agent_id: new_kp.agent_id(),
            proof,
            grace_period_secs: Some(86400),
        };
        let json = serde_json::to_string(&req).unwrap();
        let de: KeyRotationRequest = serde_json::from_str(&json).unwrap();
        assert!(de.proof.verify(&de.new_agent_id).is_ok());
        assert_eq!(de.grace_period_secs, Some(86400));
    }
}
