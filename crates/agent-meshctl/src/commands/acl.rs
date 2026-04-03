use crate::daemon::MeshdClient;
use anyhow::Result;

/// Lists all ACL rules via meshd.
pub async fn acl_list(client: &MeshdClient) -> Result<()> {
    let (status, body) = client.get("/acl").await?;
    if !status.is_success() {
        anyhow::bail!("acl list failed ({}): {}", status, body);
    }
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

/// Creates an ACL rule via meshd.
pub async fn acl_create(
    client: &MeshdClient,
    source: &str,
    target: &str,
    capabilities: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "source": source,
        "target": target,
        "allowed_capabilities": capabilities.split(',').map(|s| s.trim()).collect::<Vec<_>>(),
    });
    let (status, resp) = client.post("/acl", &body).await?;
    if status.is_success() {
        println!("ACL rule created.");
    } else {
        anyhow::bail!("acl create failed ({}): {}", status, resp);
    }
    Ok(())
}

/// Deletes an ACL rule via meshd.
pub async fn acl_delete(client: &MeshdClient, rule_id: &str) -> Result<()> {
    let (status, resp) = client.delete(&format!("/acl/{}", rule_id)).await?;
    if status.is_success() {
        println!("ACL rule deleted.");
    } else {
        anyhow::bail!("acl delete failed ({}): {}", status, resp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{delete, get, post};
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
    async fn acl_list_success() {
        let router = Router::new().route(
            "/acl",
            get(|| async {
                axum::Json(serde_json::json!([
                    {
                        "id": "rule-1",
                        "source": "agent-a",
                        "target": "agent-b",
                        "allowed_capabilities": ["scheduling"]
                    }
                ]))
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = acl_list(&client).await;
        assert!(result.is_ok(), "acl_list should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn acl_create_success() {
        let router = Router::new().route(
            "/acl",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({
                        "id": "rule-123",
                        "source": "agent-a",
                        "target": "agent-b",
                        "allowed_capabilities": ["scheduling"]
                    })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = acl_create(&client, "agent-a", "agent-b", "scheduling").await;
        assert!(result.is_ok(), "acl_create should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn acl_delete_success() {
        let router = Router::new().route(
            "/acl/{rule_id}",
            delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = acl_delete(&client, "rule-123").await;
        assert!(result.is_ok(), "acl_delete should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn acl_create_server_error() {
        let router = Router::new().route(
            "/acl",
            post(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({ "error": "source is required" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = acl_create(&client, "", "agent-b", "scheduling").await;
        assert!(result.is_err(), "acl_create should fail on server error");
    }
}
