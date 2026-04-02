use crate::daemon::MeshdClient;
use anyhow::Result;

/// Creates a new group via meshd.
pub async fn group_create(client: &MeshdClient, name: &str) -> Result<()> {
    let body = serde_json::json!({ "name": name });
    let (status, resp) = client.post("/groups", &body).await?;

    if status.is_success() {
        println!("Group created:");
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        anyhow::bail!("Group creation failed ({}): {}", status, resp);
    }
    Ok(())
}

/// Lists all groups via meshd.
pub async fn group_list(client: &MeshdClient) -> Result<()> {
    let (status, body) = client.get("/groups").await?;

    if !status.is_success() {
        anyhow::bail!("Group list request failed ({}): {}", status, body);
    }

    let count = body.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Found {count} group(s):");
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

/// Adds a member to a group via meshd.
pub async fn group_add_member(client: &MeshdClient, group_id: &str, user_id: &str) -> Result<()> {
    let path = format!("/groups/{group_id}/members");
    let body = serde_json::json!({ "user_id": user_id });
    let (status, resp) = client.post(&path, &body).await?;

    if status.is_success() {
        println!("Member {user_id} added to group {group_id}.");
    } else {
        anyhow::bail!("Add member failed ({}): {}", status, resp);
    }
    Ok(())
}

/// Removes a member from a group via meshd.
pub async fn group_remove_member(
    client: &MeshdClient,
    group_id: &str,
    user_id: &str,
) -> Result<()> {
    let path = format!("/groups/{group_id}/members/{user_id}");
    let (status, resp) = client.delete(&path).await?;

    if status.is_success() {
        println!("Member {user_id} removed from group {group_id}.");
    } else {
        anyhow::bail!("Remove member failed ({}): {}", status, resp);
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
    async fn group_create_success() {
        let router = Router::new().route(
            "/groups",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({ "id": "grp-123", "name": "my-group" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = group_create(&client, "my-group").await;
        assert!(result.is_ok(), "group_create should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn group_list_success() {
        let router = Router::new().route(
            "/groups",
            get(|| async {
                axum::Json(serde_json::json!([
                    { "id": "grp-1", "name": "groupA" },
                    { "id": "grp-2", "name": "groupB" }
                ]))
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = group_list(&client).await;
        assert!(result.is_ok(), "group_list should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn group_add_member_success() {
        let router = Router::new().route(
            "/groups/{group_id}/members",
            post(|| async { axum::http::StatusCode::NO_CONTENT }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = group_add_member(&client, "grp-123", "usr-456").await;
        assert!(
            result.is_ok(),
            "group_add_member should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn group_remove_member_success() {
        let router = Router::new().route(
            "/groups/{group_id}/members/{user_id}",
            delete(|| async { axum::http::StatusCode::NO_CONTENT }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = group_remove_member(&client, "grp-123", "usr-456").await;
        assert!(
            result.is_ok(),
            "group_remove_member should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn group_create_server_error() {
        let router = Router::new().route(
            "/groups",
            post(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({ "error": "name required" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = group_create(&client, "").await;
        assert!(result.is_err());
    }
}
