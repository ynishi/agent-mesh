use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ProtoError;

/// Agent identity derived from Ed25519 public key.
/// The AgentId is the base64url-encoded public key (44 chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        Self(URL_SAFE_NO_PAD.encode(key.as_bytes()))
    }

    /// Create from a raw string (e.g. loaded from database).
    pub fn from_raw(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey, ProtoError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.0)
            .map_err(|e| ProtoError::InvalidIdentity(format!("bad base64: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProtoError::InvalidIdentity("key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| ProtoError::InvalidIdentity(format!("bad ed25519 key: {e}")))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Newtype wrapper for AgentCard UUIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentCardId(pub Uuid);

impl AgentCardId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl fmt::Display for AgentCardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Newtype wrapper for Message UUIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Newtype wrapper for User UUIDs (reserved for v0.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Newtype wrapper for Group UUIDs (reserved for v0.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub Uuid);

impl GroupId {
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Keypair for an agent. Holds the signing (private) key.
#[derive(Debug)]
pub struct AgentKeypair {
    signing_key: SigningKey,
}

impl Clone for AgentKeypair {
    fn clone(&self) -> Self {
        Self::from_bytes(self.signing_key.as_bytes())
    }
}

impl AgentKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::from_verifying_key(&self.signing_key.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Create a copy of this keypair (re-derives from secret bytes).
    pub fn clone_inner(&self) -> Self {
        Self::from_bytes(self.signing_key.as_bytes())
    }
}

/// Verify a signature against an AgentId.
pub fn verify_signature(
    agent_id: &AgentId,
    message: &[u8],
    signature: &Signature,
) -> Result<(), ProtoError> {
    let key = agent_id.to_verifying_key()?;
    key.verify(message, signature)
        .map_err(|e| ProtoError::SignatureVerification(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let kp = AgentKeypair::generate();
        let id = kp.agent_id();
        let msg = b"hello agent mesh";
        let sig = kp.sign(msg);
        assert!(verify_signature(&id, msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let kp = AgentKeypair::generate();
        let id = kp.agent_id();
        let sig = kp.sign(b"correct");
        assert!(verify_signature(&id, b"wrong", &sig).is_err());
    }

    #[test]
    fn id_from_bytes_roundtrip() {
        let kp = AgentKeypair::generate();
        let id = kp.agent_id();
        let key = id.to_verifying_key().unwrap();
        assert_eq!(key, kp.verifying_key());
    }

    #[test]
    fn agent_card_id_roundtrip() {
        let id = AgentCardId::new_v4();
        let s = id.to_string();
        let parsed = AgentCardId::parse_str(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn message_id_roundtrip() {
        let id = MessageId::new_v4();
        let s = id.to_string();
        let parsed = MessageId::parse_str(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn serde_transparent() {
        let uuid = Uuid::new_v4();
        let id = AgentCardId(uuid);
        let json = serde_json::to_string(&id).unwrap();
        let expected = serde_json::to_string(&uuid).unwrap();
        assert_eq!(json, expected);
        let deserialized: AgentCardId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, id);
    }
}
