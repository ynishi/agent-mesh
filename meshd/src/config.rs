use anyhow::{Context, Result};
use mesh_proto::acl::AclPolicy;
use mesh_proto::identity::AgentKeypair;
use serde::{Deserialize, Serialize};

/// Configuration for a mesh node daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Ed25519 secret key (hex-encoded, 32 bytes = 64 hex chars).
    pub secret_key_hex: String,
    /// Relay server WebSocket URL.
    pub relay_url: String,
    /// Local agent HTTP endpoint to proxy requests to.
    pub local_agent_url: String,
    /// ACL policy.
    #[serde(default)]
    pub acl: AclPolicy,
}

impl NodeConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {path}"))?;
        let config: Self =
            serde_json::from_str(&content).with_context(|| "failed to parse config")?;
        Ok(config)
    }

    pub fn keypair(&self) -> Result<AgentKeypair> {
        let bytes = hex::decode(&self.secret_key_hex).with_context(|| "invalid secret_key_hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
        Ok(AgentKeypair::from_bytes(&arr))
    }

    pub fn agent_id_display(&self) -> String {
        match self.keypair() {
            Ok(kp) => kp.agent_id().to_string(),
            Err(_) => "<invalid key>".into(),
        }
    }
}
