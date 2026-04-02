use crate::commands::resolve_secret_key;
use crate::daemon::MeshdClient;
use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use anyhow::Result;

/// Registers an agent card with the registry via meshd.
pub async fn register(
    client: &MeshdClient,
    name: &str,
    description: Option<&str>,
    capabilities_csv: &str,
    secret_key: Option<&str>,
) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let caps: Vec<Capability> = capabilities_csv
        .split(',')
        .map(|s| Capability {
            name: s.trim().to_string(),
            description: None,
            input_schema: None,
            output_schema: None,
        })
        .collect();

    let reg = AgentCardRegistration {
        agent_id: kp.agent_id(),
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        capabilities: caps,
        metadata: None,
    };

    let body = serde_json::to_value(&reg)?;
    let (status, resp) = client.post("/agents", &body).await?;

    if status.is_success() {
        println!("Registered successfully:");
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        anyhow::bail!("Registration failed ({}): {}", status, resp);
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
    async fn register_success() {
        let router = Router::new().route(
            "/agents",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    axum::Json(serde_json::json!({ "status": "created" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let kp = agent_mesh_core::identity::AgentKeypair::generate();
        let secret_hex = hex::encode(kp.secret_bytes());

        let result = register(&client, "TestAgent", None, "test-cap", Some(&secret_hex)).await;
        assert!(result.is_ok(), "register should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn register_server_error() {
        let router = Router::new().route(
            "/agents",
            post(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({ "error": "internal error" })),
                )
            }),
        );

        let (sock_path, _dir) = mock_meshd_server(router).await;
        let client = MeshdClient::new(sock_path);

        let kp = agent_mesh_core::identity::AgentKeypair::generate();
        let secret_hex = hex::encode(kp.secret_bytes());

        let result = register(&client, "TestAgent", None, "cap", Some(&secret_hex)).await;
        assert!(result.is_err());
    }
}
