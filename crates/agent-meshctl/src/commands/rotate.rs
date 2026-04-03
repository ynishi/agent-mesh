use crate::daemon::MeshdClient;
use anyhow::Result;

/// Rotate the agent's Ed25519 key via meshd.
///
/// Without `--complete`: initiates rotation by generating a new keypair, signing
/// a proof with the current key, and forwarding the request to the Control Plane.
/// The new keypair is stored in meshd's memory as "pending".
///
/// With `--complete`: completes a previously initiated rotation — applies the
/// pending keypair, rewrites the config file, and reconnects to the relay.
pub async fn rotate(client: &MeshdClient, grace_period: Option<u64>, complete: bool) -> Result<()> {
    if complete {
        let (status, resp) = client
            .post("/rotate/complete", &serde_json::json!({}))
            .await?;
        if status.is_success() {
            let new_id = resp
                .get("new_agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            println!("Key rotation completed. New agent ID: {new_id}");
            println!("meshd is reconnecting to the relay with the new key.");
        } else {
            anyhow::bail!("Rotation completion failed ({}): {}", status, resp);
        }
    } else {
        let body = serde_json::json!({ "grace_period_secs": grace_period.unwrap_or(86400) });
        let (status, resp) = client.post("/rotate", &body).await?;
        if status.is_success() {
            let card_id = resp
                .get("card_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            let new_agent_id = resp
                .get("new_agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            let grace = resp
                .get("grace_period_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(86400);
            println!("Key rotation initiated.");
            println!("  Card ID:        {card_id}");
            println!("  New Agent ID:   {new_agent_id}");
            println!("  Grace period:   {grace}s");
            println!();
            println!("Both old and new keys are valid during the grace period.");
            println!("Run `meshctl rotate --complete` when ready to finalize.");
        } else {
            anyhow::bail!("Rotation initiation failed ({}): {}", status, resp);
        }
    }
    Ok(())
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
    async fn rotate_initiate_success() {
        let router = Router::new().route(
            "/rotate",
            post(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "card_id": "550e8400-e29b-41d4-a716-446655440000",
                        "new_agent_id": "newid123",
                        "grace_period_secs": 86400
                    })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let result = rotate(&client, None, false).await;
        assert!(
            result.is_ok(),
            "rotate initiate should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn rotate_complete_success() {
        let router = Router::new().route(
            "/rotate/complete",
            post(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "status": "completed",
                        "new_agent_id": "newid456"
                    })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let result = rotate(&client, None, true).await;
        assert!(
            result.is_ok(),
            "rotate complete should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn rotate_initiate_server_error() {
        let router = Router::new().route(
            "/rotate",
            post(|| async {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({ "error": "no peers" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let result = rotate(&client, None, false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rotate_complete_conflict() {
        let router = Router::new().route(
            "/rotate/complete",
            post(|| async {
                (
                    axum::http::StatusCode::CONFLICT,
                    axum::Json(
                        serde_json::json!({ "error": "no pending rotation; call POST /rotate first" }),
                    ),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let result = rotate(&client, None, true).await;
        assert!(result.is_err());
    }
}
