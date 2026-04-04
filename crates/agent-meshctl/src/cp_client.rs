//! Direct HTTP client for the Control Plane.
//!
//! Used by commands that don't need meshd (login, register, discover).
//! Reads credentials from `~/.mesh/config.toml`.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// HTTP client that communicates directly with the Control Plane.
pub struct CpClient {
    pub base_url: String,
    pub bearer_token: Option<String>,
    pub http: reqwest::Client,
}

impl CpClient {
    /// Build a CpClient from `~/.mesh/config.toml` (or overrides).
    pub fn from_config(cp_url_override: Option<&str>) -> Result<Self> {
        let mesh_dir = default_mesh_dir()?;
        let (token, stored_url) = load_credentials(&mesh_dir)?;

        let base_url = match cp_url_override {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => stored_url
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_else(|| super::DEFAULT_CP_URL.trim_end_matches('/').to_string()),
        };

        Ok(Self {
            base_url,
            bearer_token: token,
            http: reqwest::Client::new(),
        })
    }

    /// Build a CpClient without credentials (for login).
    pub fn unauthenticated(cp_url: &str) -> Self {
        Self {
            base_url: cp_url.trim_end_matches('/').to_string(),
            bearer_token: None,
            http: reqwest::Client::new(),
        }
    }

    /// GET request with Bearer auth.
    pub async fn get(&self, path: &str) -> Result<(reqwest::StatusCode, serde_json::Value)> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.get(&url);
        if let Some(ref token) = self.bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await.context("failed to reach Control Plane")?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        Ok((status, body))
    }

    /// POST request with Bearer auth and JSON body.
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<(reqwest::StatusCode, serde_json::Value)> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.post(&url).json(body);
        if let Some(ref token) = self.bearer_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await.context("failed to reach Control Plane")?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        Ok((status, body))
    }
}

fn default_mesh_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".mesh"))
}

fn load_credentials(mesh_dir: &std::path::Path) -> Result<(Option<String>, Option<String>)> {
    let path = mesh_dir.join("config.toml");
    if !path.exists() {
        return Ok((None, None));
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    #[derive(serde::Deserialize)]
    struct Creds {
        bearer_token: Option<String>,
        cp_url: Option<String>,
    }

    let creds: Creds =
        toml::from_str(&content).with_context(|| "failed to parse ~/.mesh/config.toml")?;
    Ok((creds.bearer_token, creds.cp_url))
}
