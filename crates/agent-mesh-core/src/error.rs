//! Shared [`ProtoError`] type used across this crate's identity, ACL,
//! message, and Noise transport primitives.

use thiserror::Error;

/// Errors produced by `agent-mesh-core`'s protocol, identity, and
/// cryptography primitives.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// An [`AgentId`](crate::identity::AgentId) failed to decode, or a raw
    /// key/byte value did not have the expected shape.
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),

    /// An Ed25519 signature did not verify against the claimed signer.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// An `AgentCard` (or related registration/query type) failed
    /// validation.
    #[error("invalid agent card: {0}")]
    InvalidAgentCard(String),

    /// An [`AclPolicy`](crate::acl::AclPolicy) rejected a request.
    #[error("acl denied: {0}")]
    AclDenied(String),

    /// A [`MeshEnvelope`](crate::message::MeshEnvelope) or related message
    /// type failed validation (e.g. malformed signature encoding, wrong
    /// byte length).
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// JSON (de)serialization of a protocol type failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A Noise protocol handshake or transport encrypt/decrypt operation
    /// failed.
    #[error("noise protocol error: {0}")]
    Noise(String),
}

impl From<serde_json::Error> for ProtoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
