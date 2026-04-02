use crate::commands::resolve_secret_key;
use crate::daemon::MeshdClient;
use anyhow::Result;

/// Revokes an agent's key via meshd.
///
/// Note: POST /revocations endpoint requires Subtask 3 to be implemented in meshd.
/// Until then, this will return a 404 from meshd.
pub async fn revoke(
    client: &MeshdClient,
    reason: Option<&str>,
    secret_key: Option<&str>,
) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let agent_id = kp.agent_id();

    let revocation =
        agent_mesh_core::message::KeyRevocation::new(&kp, reason.map(|s| s.to_string()));

    let body = serde_json::to_value(&revocation)?;
    let (status, resp) = client.post("/revocations", &body).await?;

    if status.is_success() {
        println!("Agent {agent_id} revoked successfully.");
        if let Some(r) = reason {
            println!("Reason: {r}");
        }
    } else {
        anyhow::bail!("Revocation failed ({}): {}", status, resp);
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
    async fn revoke_success() {
        let router = Router::new().route(
            "/revocations",
            post(|| async {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({ "status": "revoked" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let kp = agent_mesh_core::identity::AgentKeypair::generate();
        let secret_hex = hex::encode(kp.secret_bytes());

        let result = revoke(&client, Some("test reason"), Some(&secret_hex)).await;
        assert!(result.is_ok(), "revoke should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn revoke_server_error() {
        let router = Router::new().route(
            "/revocations",
            post(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({ "error": "not found" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let kp = agent_mesh_core::identity::AgentKeypair::generate();
        let secret_hex = hex::encode(kp.secret_bytes());

        let result = revoke(&client, None, Some(&secret_hex)).await;
        assert!(result.is_err());
    }
}
