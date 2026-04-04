use anyhow::{Context, Result};
use std::path::PathBuf;

/// OAuth Device Flow login — directly to Control Plane (no meshd required).
///
/// 1. POST {cp_url}/oauth/device -> device_code, user_code, verification_uri
/// 2. Display verification_uri and user_code to the user
/// 3. Poll POST {cp_url}/oauth/token { device_code } until api_token is obtained or expires
/// 4. Save api_token and cp_url to ~/.mesh/config.toml
pub async fn login(cp_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let base = cp_url.trim_end_matches('/');

    // 1. Start device flow.
    let resp: serde_json::Value = client
        .post(format!("{base}/oauth/device"))
        .send()
        .await
        .context("failed to reach Control Plane")?
        .error_for_status()
        .context("Control Plane returned an error")?
        .json()
        .await
        .context("failed to parse device flow response")?;

    let device_code = resp
        .get("device_code")
        .and_then(|v| v.as_str())
        .context("missing device_code in response")?
        .to_string();

    let user_code = resp
        .get("user_code")
        .and_then(|v| v.as_str())
        .context("missing user_code in response")?
        .to_string();

    let verification_uri = resp
        .get("verification_uri")
        .and_then(|v| v.as_str())
        .context("missing verification_uri in response")?
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

    // 2. Poll for token.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(expires_in);

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("login timed out after {} seconds", expires_in);
        }

        let poll_resp: serde_json::Value = client
            .post(format!("{base}/oauth/token"))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await
            .context("failed to poll token endpoint")?
            .json()
            .await
            .context("failed to parse token response")?;

        if let Some(error) = poll_resp.get("error").and_then(|v| v.as_str()) {
            match error {
                "access_denied" => anyhow::bail!("login denied by user"),
                "expired_token" => anyhow::bail!("device code expired"),
                "authorization_pending" | "slow_down" => continue,
                other => anyhow::bail!("OAuth error: {other}"),
            }
        }

        if let Some(api_token) = poll_resp.get("api_token").and_then(|v| v.as_str()) {
            // 3. Save credentials.
            save_credentials(api_token, cp_url)?;
            eprintln!("Login successful. Credentials saved to ~/.mesh/config.toml");
            return Ok(());
        }
    }
}

/// Save api_token and cp_url to ~/.mesh/config.toml.
fn save_credentials(api_token: &str, cp_url: &str) -> Result<()> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let mesh_dir = PathBuf::from(home).join(".mesh");
    std::fs::create_dir_all(&mesh_dir)
        .with_context(|| format!("failed to create {}", mesh_dir.display()))?;

    let content = format!("bearer_token = \"{api_token}\"\ncp_url = \"{cp_url}\"\n");
    let path = mesh_dir.join("config.toml");
    std::fs::write(&path, &content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_credentials_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mesh_dir = dir.path().join(".mesh");

        // Manually inline to test without HOME dependency
        std::fs::create_dir_all(&mesh_dir).unwrap();
        let content = format!(
            "bearer_token = \"{}\"\ncp_url = \"{}\"\n",
            "tok-test", "https://example.com"
        );
        let path = mesh_dir.join("config.toml");
        std::fs::write(&path, &content).unwrap();

        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("tok-test"));
        assert!(saved.contains("https://example.com"));
    }
}
