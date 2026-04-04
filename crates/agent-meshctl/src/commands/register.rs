use crate::cp_client::CpClient;
use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::AgentKeypair;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Registers an agent card with the registry via direct CP connection.
///
/// If `secret_key` is not provided and `MESH_SECRET_KEY` is not set,
/// a new keypair is automatically generated and saved to `~/.mesh/config.toml`.
pub async fn register(
    cp: &CpClient,
    name: &str,
    description: Option<&str>,
    capabilities_csv: &str,
    secret_key: Option<&str>,
) -> Result<()> {
    let kp = resolve_or_generate_key(secret_key)?;

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
    let (status, resp) = cp.post("/agents", &body).await?;

    if status.is_success() {
        eprintln!("Agent ID: {}", kp.agent_id());
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        anyhow::bail!("Registration failed ({}): {}", status, resp);
    }
    Ok(())
}

/// Resolve secret key from arg/env, or auto-generate and save to config.
fn resolve_or_generate_key(provided: Option<&str>) -> Result<AgentKeypair> {
    // 1. Explicit argument
    if let Some(hex_str) = provided {
        return keypair_from_hex(hex_str);
    }

    // 2. Environment variable
    if let Ok(hex_str) = std::env::var("MESH_SECRET_KEY") {
        return keypair_from_hex(&hex_str);
    }

    // 3. Existing key in config
    let mesh_dir = default_mesh_dir()?;
    if let Some(hex_str) = load_secret_key(&mesh_dir)? {
        eprintln!("Using existing key from ~/.mesh/config.toml");
        return keypair_from_hex(&hex_str);
    }

    // 4. Auto-generate
    let kp = AgentKeypair::generate();
    save_secret_key(&mesh_dir, &hex::encode(kp.secret_bytes()))?;
    eprintln!("Generated new keypair and saved to ~/.mesh/config.toml");
    Ok(kp)
}

fn keypair_from_hex(hex_str: &str) -> Result<AgentKeypair> {
    let bytes = hex::decode(hex_str).context("invalid hex in secret key")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes (64 hex chars)"))?;
    Ok(AgentKeypair::from_bytes(&arr))
}

fn default_mesh_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".mesh"))
}

fn load_secret_key(mesh_dir: &std::path::Path) -> Result<Option<String>> {
    let path = mesh_dir.join("config.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    #[derive(serde::Deserialize)]
    struct Cfg {
        secret_key: Option<String>,
    }
    let cfg: Cfg = toml::from_str(&content).unwrap_or(Cfg { secret_key: None });
    Ok(cfg.secret_key)
}

/// Append secret_key to existing config.toml (preserves bearer_token/cp_url).
fn save_secret_key(mesh_dir: &std::path::Path, hex_key: &str) -> Result<()> {
    std::fs::create_dir_all(mesh_dir)
        .with_context(|| format!("failed to create {}", mesh_dir.display()))?;

    let path = mesh_dir.join("config.toml");
    let mut content = if path.exists() {
        std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    // Append if not already present
    if !content.contains("secret_key") {
        content.push_str(&format!("secret_key = \"{hex_key}\"\n"));
    }

    std::fs::write(&path, &content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
