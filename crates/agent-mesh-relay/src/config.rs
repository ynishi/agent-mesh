use std::path::PathBuf;

use serde::Deserialize;

/// Relay configuration.
///
/// Loaded from TOML file (default: relay.toml), with CLI overrides.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    /// Listen address (host:port).
    pub listen: String,
    /// Data directory for persistent state (SQLite).
    pub data_dir: PathBuf,
    /// Rate limit: messages per second per agent.
    pub rate_limit: f64,
    /// Rate limit burst size.
    pub rate_burst: f64,
    /// Log level (RUST_LOG format).
    pub log_level: String,
    /// URL of the Control Plane for gate verification.
    /// Example: "https://cp.example.com"
    pub cp_url: Option<String>,
    /// Bearer token for authenticating with the Control Plane.
    pub cp_token: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:9800".into(),
            data_dir: PathBuf::from("data"),
            rate_limit: 50.0,
            rate_burst: 100.0,
            log_level: "info".into(),
            cp_url: None,
            cp_token: None,
        }
    }
}

impl RelayConfig {
    /// Load config from TOML file, falling back to defaults for missing fields.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let config: Self = toml::from_str(&content)?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("config file {path} not found, using defaults");
                Ok(Self::default())
            }
            Err(e) => Err(e.into()),
        }
    }
}
