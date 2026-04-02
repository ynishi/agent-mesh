use crate::commands::resolve_secret_key;
use agent_mesh_core::identity::AgentId;
use anyhow::{Context, Result};
use std::time::Duration;

/// Sends a request to a remote agent through the relay (SDK-based, direct connection).
pub async fn request(
    relay_url: &str,
    target_id: &str,
    capability: &str,
    payload_json: &str,
    secret_key: Option<&str>,
    timeout_secs: u64,
) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let target = AgentId::from_raw(target_id.to_string());

    let mut payload: serde_json::Value =
        serde_json::from_str(payload_json).context("invalid JSON payload")?;
    // Inject capability into payload for ACL routing.
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("capability".into(), serde_json::json!(capability));
    }

    let client = agent_mesh_sdk::MeshClient::connect(kp, relay_url)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    let result = client
        .request(&target, payload, Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| anyhow::anyhow!("request: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
