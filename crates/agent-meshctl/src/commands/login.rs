use crate::daemon::MeshdClient;
use anyhow::{Context, Result};

/// OAuth Device Flow login via meshd.
///
/// 1. POST /login { cp_url } -> device_code, user_code, verification_uri
/// 2. Display verification_uri and user_code to the user
/// 3. Poll POST /login/poll { device_code } until api_token is obtained or expires
pub async fn login(client: &MeshdClient, cp_url: &str) -> Result<()> {
    let body = serde_json::json!({ "cp_url": cp_url });
    let (status, resp) = client
        .post("/login", &body)
        .await
        .context("failed to initiate login")?;

    if !status.is_success() {
        anyhow::bail!("login initiation failed ({}): {}", status, resp);
    }

    let device_code = resp
        .get("device_code")
        .and_then(|v| v.as_str())
        .context("missing device_code in login response")?
        .to_string();

    let user_code = resp
        .get("user_code")
        .and_then(|v| v.as_str())
        .context("missing user_code in login response")?
        .to_string();

    let verification_uri = resp
        .get("verification_uri")
        .and_then(|v| v.as_str())
        .context("missing verification_uri in login response")?
        .to_string();

    let expires_in = resp
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);

    let interval_secs = resp.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

    eprintln!("Open the following URL to authorize:");
    eprintln!("  {verification_uri}");
    eprintln!("Enter the code: {user_code}");
    eprintln!("Waiting for authorization...");

    let poll_body = serde_json::json!({ "device_code": device_code });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(expires_in);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("login timed out after {} seconds", expires_in);
        }

        let (poll_status, poll_resp) = client
            .post("/login/poll", &poll_body)
            .await
            .context("failed to poll login status")?;

        if poll_status.is_success() {
            if poll_resp.get("api_token").is_some() {
                eprintln!("Login successful.");
                return Ok(());
            }
            // authorization_pending or slow_down: continue polling
        } else {
            let error = poll_resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if error == "access_denied" {
                anyhow::bail!("login denied by user");
            }
            if error == "expired_token" {
                anyhow::bail!("device code expired");
            }
            // For other transient errors, continue polling
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
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
    async fn login_success() {
        let router = Router::new()
            .route(
                "/login",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "device_code": "dev-code-123",
                        "user_code": "USER-CODE",
                        "verification_uri": "https://example.com/activate",
                        "expires_in": 300,
                        "interval": 0
                    }))
                }),
            )
            .route(
                "/login/poll",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "api_token": "tok-abc123"
                    }))
                }),
            );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = login(&client, "https://cp.example.com").await;
        assert!(result.is_ok(), "login should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn login_access_denied() {
        let router = Router::new()
            .route(
                "/login",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "device_code": "dev-code-456",
                        "user_code": "USER-CODE",
                        "verification_uri": "https://example.com/activate",
                        "expires_in": 300,
                        "interval": 0
                    }))
                }),
            )
            .route(
                "/login/poll",
                post(|| async {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({ "error": "access_denied" })),
                    )
                }),
            );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = login(&client, "https://cp.example.com").await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("denied"), "expected denial error: {msg}");
    }
}
