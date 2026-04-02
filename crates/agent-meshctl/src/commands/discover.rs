use crate::daemon::MeshdClient;
use anyhow::Result;

/// Searches for agents in the registry via meshd.
pub async fn discover(
    client: &MeshdClient,
    capability: Option<&str>,
    search: Option<&str>,
) -> Result<()> {
    let mut params = Vec::new();
    if let Some(c) = capability {
        params.push(format!("capability={c}"));
    }
    if let Some(s) = search {
        params.push(format!("search={s}"));
    }
    let query_str = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    let path = format!("/agents{query_str}");
    let (status, body) = client.get(&path).await?;

    if !status.is_success() {
        anyhow::bail!("discover request failed ({}): {}", status, body);
    }

    let agents = body.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Found {agents} agent(s):");
    println!("{}", serde_json::to_string_pretty(&body)?);
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
    async fn discover_returns_agents() {
        let router = Router::new().route(
            "/agents",
            get(|| async {
                axum::Json(serde_json::json!([
                    { "name": "AgentA", "capabilities": ["cap1"] },
                    { "name": "AgentB", "capabilities": ["cap2"] }
                ]))
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = discover(&client, None, None).await;
        assert!(result.is_ok(), "discover should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn discover_with_capability_filter() {
        let router = Router::new().route(
            "/agents",
            get(
                |axum::extract::Query(params): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    let cap = params.get("capability").cloned().unwrap_or_default();
                    if cap == "scheduling" {
                        axum::Json(serde_json::json!([{ "name": "SchedulerAgent" }]))
                    } else {
                        axum::Json(serde_json::json!([]))
                    }
                },
            ),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = discover(&client, Some("scheduling"), None).await;
        assert!(
            result.is_ok(),
            "discover with filter should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn discover_server_error() {
        let router = Router::new().route(
            "/agents",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({ "error": "internal" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);
        let result = discover(&client, None, None).await;
        assert!(result.is_err());
    }
}
