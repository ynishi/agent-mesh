use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::identity::AgentKeypair;
use anyhow::{Context, Result};
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
    /// ACL policy (inline).
    #[serde(default)]
    pub acl: AclPolicy,
    /// Path to the config file (set internally for hot reload).
    #[serde(skip)]
    pub config_path: Option<String>,
}

impl NodeConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {path}"))?;
        let mut config: Self =
            serde_json::from_str(&content).with_context(|| "failed to parse config")?;
        config.config_path = Some(path.to_string());
        Ok(config)
    }

    /// Build config from CLI args, optionally loading a config file as base.
    /// CLI args override config file values.
    pub fn from_cli(
        config_path: Option<&str>,
        relay: Option<&str>,
        local_agent: Option<&str>,
        secret_key: Option<&str>,
        acl_path: Option<&str>,
    ) -> Result<Self> {
        let mut cfg = if let Some(path) = config_path {
            Self::load(path)?
        } else {
            Self {
                secret_key_hex: String::new(),
                relay_url: String::new(),
                local_agent_url: String::new(),
                acl: AclPolicy::default(),
                config_path: None,
            }
        };

        if let Some(relay) = relay {
            cfg.relay_url = relay.to_string();
        }
        if let Some(agent) = local_agent {
            cfg.local_agent_url = agent.to_string();
        }
        if let Some(key) = secret_key {
            cfg.secret_key_hex = key.to_string();
        }
        if let Some(acl_path) = acl_path {
            let content = std::fs::read_to_string(acl_path)
                .with_context(|| format!("failed to read ACL file: {acl_path}"))?;
            cfg.acl = serde_json::from_str(&content).with_context(|| "failed to parse ACL file")?;
        }

        Ok(cfg)
    }

    /// Reload ACL policy from the config file.
    pub fn reload_acl(path: &str) -> Result<AclPolicy> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config for reload: {path}"))?;
        let config: Self =
            serde_json::from_str(&content).with_context(|| "failed to parse config for reload")?;
        Ok(config.acl)
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
