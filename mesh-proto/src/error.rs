use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("invalid agent card: {0}")]
    InvalidAgentCard(String),

    #[error("acl denied: {0}")]
    AclDenied(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for ProtoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
