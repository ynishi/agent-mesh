use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::identity::AgentKeypair;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    /// Control Plane URL (e.g., "http://localhost:9801").
    #[serde(default)]
    pub cp_url: Option<String>,
    /// Bearer token for CP authentication (loaded from ~/.mesh/config.toml).
    #[serde(skip)]
    pub bearer_token: Option<String>,
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
        cp_url: Option<&str>,
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
                cp_url: None,
                bearer_token: None,
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
        if let Some(url) = cp_url {
            cfg.cp_url = Some(url.to_string());
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

/// Credentials stored in `~/.mesh/config.toml`.
///
/// Separated from `NodeConfig` (JSON) so the bearer token is never written to the
/// node config file.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MeshCredentials {
    pub bearer_token: Option<String>,
    pub cp_url: Option<String>,
}

impl MeshCredentials {
    /// Load from `<mesh_dir>/config.toml`.  Returns `Default` when the file does not exist.
    pub fn load(mesh_dir: &Path) -> Result<Self> {
        let path = mesh_dir.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let creds: Self =
            toml::from_str(&content).with_context(|| "failed to parse ~/.mesh/config.toml")?;
        Ok(creds)
    }

    /// Save to `<mesh_dir>/config.toml`, creating the directory if needed.
    /// Sets 0600 permissions on Unix so only the owner can read the token.
    pub fn save(&self, mesh_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(mesh_dir)
            .with_context(|| format!("failed to create dir {}", mesh_dir.display()))?;
        let path = mesh_dir.join("config.toml");
        let content = toml::to_string(self).with_context(|| "failed to serialize credentials")?;
        std::fs::write(&path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }

        Ok(())
    }

    /// Returns the default `~/.mesh/` directory path.
    pub fn default_mesh_dir() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home).join(".mesh"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_secret_hex() -> String {
        let kp = AgentKeypair::generate();
        hex::encode(kp.secret_bytes())
    }

    #[test]
    fn from_cli_no_config_file() {
        let secret = valid_secret_hex();
        let cfg = NodeConfig::from_cli(
            None,
            Some("ws://localhost:9800/ws"),
            Some("http://localhost:8080"),
            Some(&secret),
            None,
            None,
        )
        .unwrap();

        assert_eq!(cfg.relay_url, "ws://localhost:9800/ws");
        assert_eq!(cfg.local_agent_url, "http://localhost:8080");
        assert_eq!(cfg.secret_key_hex, secret);
        assert!(cfg.acl.rules.is_empty());
    }

    #[test]
    fn from_cli_defaults_are_empty() {
        let cfg = NodeConfig::from_cli(None, None, None, None, None, None).unwrap();
        assert!(cfg.relay_url.is_empty());
        assert!(cfg.local_agent_url.is_empty());
        assert!(cfg.secret_key_hex.is_empty());
    }

    #[test]
    fn from_cli_cp_url() {
        let cfg = NodeConfig::from_cli(None, None, None, None, None, Some("http://cp.example.com"))
            .unwrap();
        assert_eq!(cfg.cp_url.as_deref(), Some("http://cp.example.com"));
    }

    #[test]
    fn keypair_valid() {
        let secret = valid_secret_hex();
        let cfg = NodeConfig {
            secret_key_hex: secret.clone(),
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: AclPolicy::default(),
            config_path: None,
            cp_url: None,
            bearer_token: None,
        };
        let kp = cfg.keypair().unwrap();
        assert!(!kp.agent_id().as_str().is_empty());
    }

    #[test]
    fn keypair_invalid_hex() {
        let cfg = NodeConfig {
            secret_key_hex: "not-hex".into(),
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: AclPolicy::default(),
            config_path: None,
            cp_url: None,
            bearer_token: None,
        };
        assert!(cfg.keypair().is_err());
    }

    #[test]
    fn keypair_wrong_length() {
        let cfg = NodeConfig {
            secret_key_hex: "abcd".into(),
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: AclPolicy::default(),
            config_path: None,
            cp_url: None,
            bearer_token: None,
        };
        assert!(cfg.keypair().is_err());
    }

    #[test]
    fn agent_id_display_valid() {
        let secret = valid_secret_hex();
        let cfg = NodeConfig {
            secret_key_hex: secret,
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: AclPolicy::default(),
            config_path: None,
            cp_url: None,
            bearer_token: None,
        };
        let display = cfg.agent_id_display();
        assert_ne!(display, "<invalid key>");
        assert!(!display.is_empty());
    }

    #[test]
    fn agent_id_display_invalid() {
        let cfg = NodeConfig {
            secret_key_hex: "bad".into(),
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: AclPolicy::default(),
            config_path: None,
            cp_url: None,
            bearer_token: None,
        };
        assert_eq!(cfg.agent_id_display(), "<invalid key>");
    }

    #[test]
    fn load_config_file() {
        let secret = valid_secret_hex();
        let dir = std::env::temp_dir().join("meshd-test-load");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let json = serde_json::json!({
            "secret_key_hex": secret,
            "relay_url": "ws://example.com/ws",
            "local_agent_url": "http://localhost:9000",
            "acl": { "default_deny": true, "rules": [] }
        });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cfg = NodeConfig::load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.relay_url, "ws://example.com/ws");
        assert_eq!(cfg.local_agent_url, "http://localhost:9000");
        assert!(cfg.acl.default_deny);
        assert_eq!(cfg.config_path.as_deref(), Some(path.to_str().unwrap()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_cli_overrides_config_file() {
        let secret = valid_secret_hex();
        let dir = std::env::temp_dir().join("meshd-test-override");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let json = serde_json::json!({
            "secret_key_hex": secret,
            "relay_url": "ws://file.com/ws",
            "local_agent_url": "http://file:8080",
        });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cfg = NodeConfig::from_cli(
            Some(path.to_str().unwrap()),
            Some("ws://cli.com/ws"),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        // CLI relay overrides file.
        assert_eq!(cfg.relay_url, "ws://cli.com/ws");
        // File value preserved when CLI not specified.
        assert_eq!(cfg.local_agent_url, "http://file:8080");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // MeshCredentials tests

    #[test]
    fn mesh_credentials_load_missing_file() {
        let dir = std::env::temp_dir().join("meshd-test-creds-missing");
        // Ensure the dir does not contain config.toml
        let _ = std::fs::remove_file(dir.join("config.toml"));
        let creds = MeshCredentials::load(&dir).unwrap();
        assert!(creds.bearer_token.is_none());
        assert!(creds.cp_url.is_none());
    }

    #[test]
    fn mesh_credentials_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("meshd-test-creds-roundtrip");
        std::fs::create_dir_all(&dir).unwrap();

        let creds = MeshCredentials {
            bearer_token: Some("tok-abc123".into()),
            cp_url: Some("http://cp.local:9801".into()),
        };
        creds.save(&dir).unwrap();

        let loaded = MeshCredentials::load(&dir).unwrap();
        assert_eq!(loaded.bearer_token.as_deref(), Some("tok-abc123"));
        assert_eq!(loaded.cp_url.as_deref(), Some("http://cp.local:9801"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn mesh_credentials_save_sets_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("meshd-test-creds-perms");
        std::fs::create_dir_all(&dir).unwrap();

        let creds = MeshCredentials {
            bearer_token: Some("tok-secret".into()),
            cp_url: None,
        };
        creds.save(&dir).unwrap();

        let meta = std::fs::metadata(dir.join("config.toml")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 but got {mode:o}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mesh_credentials_default_mesh_dir() {
        // HOME must be set in test environment.
        if std::env::var("HOME").is_ok() {
            let dir = MeshCredentials::default_mesh_dir().unwrap();
            assert!(dir.ends_with(".mesh"));
        }
    }
}
