use crate::daemon::MeshdClient;
use anyhow::Result;

/// Shows meshd connection status.
pub async fn status(client: &MeshdClient) -> Result<()> {
    let (status_code, body) = client.get("/status").await?;

    if !status_code.is_success() {
        anyhow::bail!("status request failed: {}", status_code);
    }

    let state = body
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let cp_url = body
        .get("cp_url")
        .and_then(|v| v.as_str())
        .unwrap_or("(not configured)");
    let has_token = body
        .get("has_token")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    println!("Meshd Status:");
    println!("  State:       {state}");
    println!("  CP URL:      {cp_url}");
    println!("  Has Token:   {has_token}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use std::future::IntoFuture;
    use std::path::PathBuf;

    async fn mock_meshd_server(router: Router) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("meshd.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind");
        tokio::spawn(axum::serve(listener, router.into_make_service()).into_future());
        (sock_path, dir)
    }

    #[tokio::test]
    async fn status_success() {
        let router = Router::new().route(
            "/status",
            get(|| async {
                axum::Json(serde_json::json!({
                    "state": "connected",
                    "cp_url": "https://cp.example.com",
                    "has_token": true
                }))
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = status(&client).await;
        assert!(result.is_ok(), "status should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn status_server_error() {
        let router = Router::new().route(
            "/status",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({ "error": "internal" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = status(&client).await;
        assert!(result.is_err());
    }
}
