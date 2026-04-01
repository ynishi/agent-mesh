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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;

    async fn mock_server(handler: axum::routing::MethodRouter) -> String {
        let app = axum::Router::new().route("/", handler);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());
        format!("http://127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn forward_json_response() {
        let url = mock_server(axum::routing::post(
            |axum::Json(body): axum::Json<Value>| async move {
                axum::Json(serde_json::json!({
                    "echo": body,
                    "status": "ok",
                }))
            },
        ))
        .await;

        let payload = serde_json::json!({"capability": "scheduling"});
        let result = forward_to_local(&url, &payload).await.unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["echo"]["capability"], "scheduling");
    }

    #[tokio::test]
    async fn forward_connection_refused() {
        let result = forward_to_local("http://127.0.0.1:1", &serde_json::json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn forward_non_json_response() {
        let url = mock_server(axum::routing::post(|| async { "plain text" })).await;

        let result = forward_to_local(&url, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(result["error"], "non-json response");
    }
}
