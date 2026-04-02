use agent_mesh_core::acl::AclRule;
use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use anyhow::{Context, Result};
use std::time::Duration;

pub fn resolve_secret_key(provided: Option<&str>) -> Result<AgentKeypair> {
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

    let client = agent_mesh_sdk::MeshClient::connect(kp, relay_url)
        .await
        .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    let result = client
        .request(&target, payload, Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| anyhow::anyhow!("request: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub async fn status(relay_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client.get(format!("{relay_url}/status")).send().await?;

    let status_code = resp.status();
    if !status_code.is_success() {
        anyhow::bail!("status request failed: {}", status_code);
    }

    let body: serde_json::Value = resp.json().await?;
    let connected = body
        .get("connected_agents")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let buffered = body
        .get("buffered_agents")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let revoked = body
        .get("revoked_agents")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("Relay Status:");
    println!("  Connected agents: {connected}");
    println!("  Buffered agents:  {buffered}");
    println!("  Revoked agents:   {revoked}");

    if let Some(agents) = body.get("agents").and_then(|v| v.as_array()) {
        if !agents.is_empty() {
            println!("  Online:");
            for a in agents {
                if let Some(id) = a.as_str() {
                    println!("    - {id}");
                }
            }
        }
    }
    Ok(())
}

pub async fn revoke(relay_url: &str, reason: Option<&str>, secret_key: Option<&str>) -> Result<()> {
    let kp = resolve_secret_key(secret_key)?;
    let agent_id = kp.agent_id();

    let revocation =
        agent_mesh_core::message::KeyRevocation::new(&kp, reason.map(|s| s.to_string()));

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

/// Build an ACL rule value (testable version without stdout).
pub fn build_acl_rule(source_id: &str, target_id: &str, allow_csv: &str) -> AclRule {
    AclRule {
        source: AgentId::from_raw(source_id.to_string()),
        target: AgentId::from_raw(target_id.to_string()),
        allowed_capabilities: allow_csv.split(',').map(|s| s.trim().to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_secret_hex() -> String {
        let kp = AgentKeypair::generate();
        hex::encode(kp.secret_bytes())
    }

    #[test]
    fn resolve_secret_key_from_arg() {
        let hex = valid_secret_hex();
        let kp = resolve_secret_key(Some(&hex)).unwrap();
        assert!(!kp.agent_id().as_str().is_empty());
    }

    #[test]
    fn resolve_secret_key_invalid_hex() {
        let result = resolve_secret_key(Some("not-hex"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_secret_key_wrong_length() {
        let result = resolve_secret_key(Some("abcd"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_secret_key_no_arg_no_env() {
        // Unset env to ensure test isolation.
        std::env::remove_var("MESH_SECRET_KEY");
        let result = resolve_secret_key(None);
        assert!(result.is_err());
    }

    #[test]
    fn keygen_succeeds() {
        // keygen() prints to stdout and always succeeds.
        keygen().unwrap();
    }

    #[test]
    fn build_acl_rule_single_capability() {
        let rule = build_acl_rule("alice-id", "bob-id", "scheduling");
        assert_eq!(rule.source.as_str(), "alice-id");
        assert_eq!(rule.target.as_str(), "bob-id");
        assert_eq!(rule.allowed_capabilities, vec!["scheduling"]);
    }

    #[test]
    fn build_acl_rule_multiple_capabilities() {
        let rule = build_acl_rule("alice", "bob", "scheduling, availability, contact");
        assert_eq!(rule.allowed_capabilities.len(), 3);
        assert_eq!(rule.allowed_capabilities[0], "scheduling");
        assert_eq!(rule.allowed_capabilities[1], "availability");
        assert_eq!(rule.allowed_capabilities[2], "contact");
    }

    #[test]
    fn acl_json_roundtrip() {
        let rule = build_acl_rule("src", "tgt", "cap1,cap2");
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: AclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source.as_str(), "src");
        assert_eq!(parsed.target.as_str(), "tgt");
        assert_eq!(parsed.allowed_capabilities, vec!["cap1", "cap2"]);
    }

    /// Setup a test user+group+token directly in the registry DB.
    /// Returns (raw_token) that can be used as `Authorization: Bearer <token>`.
    fn setup_registry_auth(db: &std::sync::Arc<agent_mesh_registry::db::Database>) -> String {
        use agent_mesh_core::identity::{GroupId, UserId};
        use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};
        use agent_mesh_registry::auth::hash_token;

        let user = User {
            id: UserId::new_v4(),
            external_id: format!("test-{}", uuid::Uuid::new_v4()),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        db.create_user(&user).expect("create user");

        let group = Group {
            id: GroupId::new_v4(),
            name: "test-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).expect("create group");
        db.add_group_member(&GroupMember {
            group_id: group.id,
            user_id: user.id,
            role: GroupRole::Owner,
        })
        .expect("add member");

        let raw_token = format!("tok-{}", uuid::Uuid::new_v4());
        let token = ApiToken {
            token_hash: hash_token(&raw_token),
            user_id: user.id,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        db.create_api_token(&token).expect("create token");

        raw_token
    }

    #[tokio::test]
    async fn discover_against_real_registry() {
        use std::future::IntoFuture;
        use std::sync::Arc;

        let db = Arc::new(agent_mesh_registry::db::Database::open(":memory:").unwrap());
        let state = agent_mesh_registry::AppState { db: db.clone() };
        let app = agent_mesh_registry::app(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let registry_url = format!("http://127.0.0.1:{}", addr.port());
        let raw_token = setup_registry_auth(&db);

        // Register an agent with auth token.
        let kp = AgentKeypair::generate();
        let reg = agent_mesh_core::agent_card::AgentCardRegistration {
            agent_id: kp.agent_id(),
            name: "TestAgent".to_string(),
            description: None,
            capabilities: vec![agent_mesh_core::agent_card::Capability {
                name: "test-cap".to_string(),
                description: None,
                input_schema: None,
                output_schema: None,
            }],
            metadata: None,
        };
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{registry_url}/agents"))
            .header("Authorization", format!("Bearer {raw_token}"))
            .json(&reg)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "register failed");

        // Discover by capability with auth token.
        let resp = client
            .get(format!("{registry_url}/agents?capability=test-cap"))
            .header("Authorization", format!("Bearer {raw_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["name"], "TestAgent");
    }

    #[tokio::test]
    async fn status_against_real_relay() {
        use std::future::IntoFuture;
        use std::sync::Arc;

        let hub = Arc::new(agent_mesh_relay::hub::Hub::with_rate_limit(100.0, 200.0));
        let app = agent_mesh_relay::app(hub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let relay_url = format!("http://127.0.0.1:{}", addr.port());
        status(&relay_url).await.unwrap();
    }
}
