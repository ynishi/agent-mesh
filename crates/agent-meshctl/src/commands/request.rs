use crate::daemon::MeshdClient;
use anyhow::{Context, Result};

/// Sends a request to a remote agent through meshd Local API (`POST /request`).
pub async fn request(
    client: &MeshdClient,
    target_id: &str,
    capability: &str,
    payload_json: &str,
    timeout_secs: u64,
) -> Result<()> {
    let payload: serde_json::Value =
        serde_json::from_str(payload_json).context("invalid JSON payload")?;

    let body = serde_json::json!({
        "target": target_id,
        "capability": capability,
        "payload": payload,
        "timeout_secs": timeout_secs,
    });

    let (status, resp) = client.post("/request", &body).await?;

    if !status.is_success() {
        anyhow::bail!("request failed ({}): {}", status, resp);
    }

    let result = resp.get("payload").unwrap_or(&resp);
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}
