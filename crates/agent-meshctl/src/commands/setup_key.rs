use crate::daemon::MeshdClient;
use anyhow::Result;

/// Creates a new setup key via meshd.
///
/// # Arguments
/// * `group_id` - The group this setup key is scoped to.
/// * `usage` - Either `"one-off"` (single use) or `"reusable"`.
/// * `max_uses` - Maximum number of uses (only relevant for `"reusable"`).
/// * `expires_in_hours` - Validity period in hours from now.
pub async fn setup_key_create(
    client: &MeshdClient,
    group_id: &str,
    usage: &str,
    max_uses: Option<u32>,
    expires_in_hours: u64,
) -> Result<()> {
    let mut body = serde_json::json!({
        "group_id": group_id,
        "usage": usage,
        "expires_in_hours": expires_in_hours,
    });

    if let Some(n) = max_uses {
        body["max_uses"] = serde_json::Value::Number(n.into());
    }

    let (status, resp) = client.post("/setup-keys", &body).await?;

    if status.is_success() {
        println!("Setup key created:");
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        anyhow::bail!("Setup key creation failed ({}): {}", status, resp);
    }
    Ok(())
}

/// Lists all setup keys for the authenticated user via meshd.
pub async fn setup_key_list(client: &MeshdClient) -> Result<()> {
    let (status, body) = client.get("/setup-keys").await?;

    if !status.is_success() {
        anyhow::bail!("Setup key list request failed ({}): {}", status, body);
    }

    let count = body.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Found {count} setup key(s):");
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

/// Revokes a setup key by ID via meshd.
pub async fn setup_key_revoke(client: &MeshdClient, id: &str) -> Result<()> {
    let path = format!("/setup-keys/{id}");
    let (status, resp) = client.delete(&path).await?;

    if status.is_success() {
        println!("Setup key {id} revoked.");
    } else {
        anyhow::bail!("Setup key revocation failed ({}): {}", status, resp);
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
    async fn setup_key_create_success() {
        let router = Router::new().route(
            "/setup-keys",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({
                        "id": "sk-uuid-1",
                        "key": "sk_abc123",
                        "usage": "one-off"
                    })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_create(&client, "grp-1", "one-off", None, 24).await;
        assert!(
            result.is_ok(),
            "setup_key_create should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn setup_key_create_reusable_with_max_uses() {
        let router = Router::new().route(
            "/setup-keys",
            post(
                |axum::Json(body): axum::Json<serde_json::Value>| async move {
                    assert_eq!(body["usage"], "reusable");
                    assert_eq!(body["max_uses"], 5);
                    (
                        axum::http::StatusCode::CREATED,
                        axum::Json(serde_json::json!({"id": "sk-uuid-2", "usage": "reusable"})),
                    )
                },
            ),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_create(&client, "grp-1", "reusable", Some(5), 48).await;
        assert!(
            result.is_ok(),
            "setup_key_create reusable should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn setup_key_create_server_error() {
        let router = Router::new().route(
            "/setup-keys",
            post(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({"error": "invalid group_id"})),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_create(&client, "", "one-off", None, 24).await;
        assert!(
            result.is_err(),
            "setup_key_create should fail on server error"
        );
    }

    #[tokio::test]
    async fn setup_key_list_success() {
        let router = Router::new().route(
            "/setup-keys",
            get(|| async {
                axum::Json(serde_json::json!([
                    {"id": "sk-1", "usage": "one-off"},
                    {"id": "sk-2", "usage": "reusable"}
                ]))
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_list(&client).await;
        assert!(result.is_ok(), "setup_key_list should succeed: {result:?}");
    }

    #[tokio::test]
    async fn setup_key_list_server_error() {
        let router = Router::new().route(
            "/setup-keys",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({"error": "db error"})),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_list(&client).await;
        assert!(
            result.is_err(),
            "setup_key_list should fail on server error"
        );
    }

    #[tokio::test]
    async fn setup_key_revoke_success() {
        let router = Router::new().route(
            "/setup-keys/{id}",
            delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_revoke(&client, "sk-uuid-1").await;
        assert!(
            result.is_ok(),
            "setup_key_revoke should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn setup_key_revoke_not_found() {
        let router = Router::new().route(
            "/setup-keys/{id}",
            delete(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error": "not found"})),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = setup_key_revoke(&client, "nonexistent").await;
        assert!(
            result.is_err(),
            "setup_key_revoke should fail when not found"
        );
    }
}
