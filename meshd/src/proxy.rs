use anyhow::Result;
use serde_json::Value;

/// Forward a request payload to the local agent via HTTP POST.
pub async fn forward_to_local(local_url: &str, payload: &Value) -> Result<Value> {
    let client = reqwest::Client::new();
    let resp = client
        .post(local_url)
        .json(payload)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_else(
        |_| serde_json::json!({"error": "non-json response", "status": status.as_u16()}),
    );

    Ok(body)
}
