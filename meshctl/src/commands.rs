use anyhow::{Context, Result};
use mesh_proto::acl::AclRule;
use mesh_proto::agent_card::{AgentCardRegistration, Capability};
use mesh_proto::identity::{AgentId, AgentKeypair};
use std::time::Duration;

fn resolve_secret_key(provided: Option<&str>) -> Result<AgentKeypair> {
    let hex_str = match provided {
        Some(s) => s.to_string(),
        None => std::env::var("MESH_SECRET_KEY")
            .context("no --secret-key provided and MESH_SECRET_KEY env not set")?,
    };
    let bytes = hex::decode(&hex_str).context("invalid hex in secret key")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes (64 hex chars)"))?;
    Ok(AgentKeypair::from_bytes(&arr))
}

pub fn keygen() -> Result<()> {
    let kp = AgentKeypair::generate();
    let secret_hex = hex::encode(kp.secret_bytes());
    let agent_id = kp.agent_id();
    println!("Agent ID:    {agent_id}");
    println!("Secret Key:  {secret_hex}");
    println!();
    println!("Save the secret key securely. The Agent ID is derived from it.");
    Ok(())
}

pub async fn register(
    registry_url: &str,
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

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{registry_url}/agents"))
        .json(&reg)
        .send()
        .await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    if status.is_success() {
        println!("Registered successfully:");
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        anyhow::bail!("Registration failed ({}): {}", status, body);
    }
    Ok(())
}

pub async fn discover(
    registry_url: &str,
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

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{registry_url}/agents{query_str}"))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let agents = body.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Found {agents} agent(s):");
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

pub async fn request(
    relay_url: &str,
    target_id: &str,
    capability: &str,
    payload_json: &str,
    secret_key: Option<&str>,
    timeout_secs: u64,
) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let target = AgentId::from_raw(target_id.to_string());

    let mut payload: serde_json::Value =
        serde_json::from_str(payload_json).context("invalid JSON payload")?;
    // Inject capability into payload for ACL routing.
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("capability".into(), serde_json::json!(capability));
    }

    let client = mesh_sdk::MeshClient::connect(kp, relay_url)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    let result = client
        .request(&target, payload, Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| anyhow::anyhow!("request: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub async fn revoke(relay_url: &str, reason: Option<&str>, secret_key: Option<&str>) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let agent_id = kp.agent_id();

    let revocation = mesh_proto::message::KeyRevocation::new(&kp, reason.map(|s| s.to_string()));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{relay_url}/revoke"))
        .json(&revocation)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;
    if status.is_success() {
        println!("Agent {agent_id} revoked successfully.");
        if let Some(r) = reason {
            println!("Reason: {r}");
        }
    } else {
        anyhow::bail!("Revocation failed ({}): {}", status, body);
    }
    Ok(())
}

pub fn acl(source_id: &str, target_id: &str, allow_csv: &str) -> Result<()> {
    let rule = AclRule {
        source: AgentId::from_raw(source_id.to_string()),
        target: AgentId::from_raw(target_id.to_string()),
        allowed_capabilities: allow_csv.split(',').map(|s| s.trim().to_string()).collect(),
    };
    println!("{}", serde_json::to_string_pretty(&rule)?);
    Ok(())
}
