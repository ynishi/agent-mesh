use std::future::IntoFuture;
use std::sync::Arc;

use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::{AgentCardId, AgentKeypair, GroupId, UserId};
use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};
use agent_mesh_core::user::{
    ApiToken, Group, GroupMember, GroupRole, SetupKey, SetupKeyUsage, User,
};
use agent_mesh_registry::auth::hash_token;
use agent_mesh_registry::db::Database;
use agent_mesh_registry::sync::SyncHub;
use agent_mesh_registry::AppState;
use uuid::Uuid;

async fn start_registry() -> (String, Arc<Database>) {
    let db = Arc::new(Database::open(":memory:").expect("in-memory db"));
    let state = AppState {
        db: db.clone(),
        oauth_config: None,
        http_client: reqwest::Client::new(),
        sync_hub: Arc::new(SyncHub::new()),
    };
    let app = agent_mesh_registry::app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    (format!("http://127.0.0.1:{}", addr.port()), db)
}

/// Create a test user, group, and API token. Returns (user_id, group_id, raw_token).
fn setup_auth(db: &Arc<Database>) -> (UserId, String) {
    let (user_id, _group_id, raw_token) = setup_auth_with_group(db);
    (user_id, raw_token)
}

/// Create a test user, group, and API token. Returns (user_id, group_id, raw_token).
fn setup_auth_with_group(db: &Arc<Database>) -> (UserId, GroupId, String) {
    let user = User {
        id: UserId::new_v4(),
        external_id: format!("test-user-{}", Uuid::new_v4()),
        provider: "test".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: chrono::Utc::now(),
    };
    db.create_user(&user).expect("create test user");

    let group = Group {
        id: GroupId::new_v4(),
        name: "test-group".to_string(),
        created_by: user.id,
        created_at: chrono::Utc::now(),
    };
    db.create_group(&group).expect("create test group");
    db.add_group_member(&GroupMember {
        group_id: group.id,
        user_id: user.id,
        role: GroupRole::Owner,
    })
    .expect("add group member");

    let raw_token = format!("test-token-{}", Uuid::new_v4());
    let token = ApiToken {
        token_hash: hash_token(&raw_token),
        user_id: user.id,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    db.create_api_token(&token).expect("create api token");

    (user.id, group.id, raw_token)
}

fn make_registration(agent_id: &str, name: &str, caps: &[&str]) -> AgentCardRegistration {
    AgentCardRegistration {
        agent_id: agent_mesh_core::identity::AgentId::from_raw(agent_id.to_string()),
        name: name.to_string(),
        description: Some(format!("{name} agent")),
        capabilities: caps
            .iter()
            .map(|c| Capability {
                name: c.to_string(),
                description: None,
                input_schema: None,
                output_schema: None,
            })
            .collect(),
        metadata: None,
    }
}

// ── Normal path tests (with auth) ─────────────────────────────────────────────

#[tokio::test]
async fn health_check() {
    let (base, _db) = start_registry().await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn health_no_auth_required() {
    // /health must be accessible without any Authorization header.
    let (base, _db) = start_registry().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn register_agent_card() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let kp = AgentKeypair::generate();
    let reg = make_registration(
        kp.agent_id().as_str(),
        "Bob",
        &["scheduling", "availability"],
    );

    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let card: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(card["name"], "Bob");
    assert_eq!(card["agent_id"], kp.agent_id().as_str());
    assert_eq!(card["capabilities"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn search_by_capability() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    // Register two agents with different capabilities.
    let reg1 = make_registration("agent-1", "Alice", &["scheduling", "contact"]);
    let reg2 = make_registration("agent-2", "Bob", &["billing"]);

    client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg1)
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg2)
        .send()
        .await
        .unwrap();

    // Search for scheduling — only Alice.
    let resp = client
        .get(format!("{base}/agents?capability=scheduling"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["name"], "Alice");
}

#[tokio::test]
async fn search_returns_all_without_filter() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let reg1 = make_registration("agent-1", "Alice", &["scheduling"]);
    let reg2 = make_registration("agent-2", "Bob", &["billing"]);

    client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg1)
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg2)
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 2);
}

#[tokio::test]
async fn get_agent_by_id() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fetched["name"], "Alice");
}

#[tokio::test]
async fn get_agent_not_found() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/agents/00000000-0000-0000-0000-000000000000"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn update_agent_card() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let updated_reg = make_registration("agent-1", "Alice v2", &["scheduling", "contact"]);
    let resp = client
        .put(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&updated_reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["name"], "Alice v2");
    assert_eq!(updated["capabilities"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn delete_agent_card() {
    let (base, db) = start_registry().await;
    let (_user_id, token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let resp = client
        .delete(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Confirm gone.
    let resp = client
        .get(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Auth failure tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn register_agent_without_auth() {
    let (base, _db) = start_registry().await;
    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = reqwest::Client::new()
        .post(format!("{base}/agents"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn search_agents_without_auth() {
    let (base, _db) = start_registry().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/agents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ── Ownership tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn update_agent_wrong_owner() {
    let (base, db) = start_registry().await;
    let (_owner_id, owner_token) = setup_auth(&db);
    let (_other_id, other_token) = setup_auth(&db);
    let client = reqwest::Client::new();

    // Owner registers an agent.
    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {owner_token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    // Other user tries to update — must get 403.
    let updated_reg = make_registration("agent-1", "Alice Hacked", &["scheduling"]);
    let resp = client
        .put(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {other_token}"))
        .json(&updated_reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn delete_agent_wrong_owner() {
    let (base, db) = start_registry().await;
    let (_owner_id, owner_token) = setup_auth(&db);
    let (_other_id, other_token) = setup_auth(&db);
    let client = reqwest::Client::new();

    // Owner registers an agent.
    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {owner_token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    // Other user tries to delete — must get 403.
    let resp = client
        .delete(format!("{base}/agents/{id}"))
        .header("Authorization", format!("Bearer {other_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ── register_with_setup_key tests ────────────────────────────────────────────

fn make_setup_key(
    db: &Arc<Database>,
    user_id: UserId,
    group_id: GroupId,
    raw_key: &str,
    usage: SetupKeyUsage,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> SetupKey {
    let uses_remaining = match &usage {
        SetupKeyUsage::OneOff => None,
        SetupKeyUsage::Reusable { max_uses } => Some(*max_uses),
    };
    let key = SetupKey {
        id: Uuid::new_v4(),
        key_hash: hash_token(raw_key),
        user_id,
        group_id,
        usage,
        uses_remaining,
        created_at: chrono::Utc::now(),
        expires_at,
    };
    db.create_setup_key(&key).expect("create setup key");
    key
}

#[tokio::test]
async fn register_with_setup_key_success() {
    let (base, db) = start_registry().await;
    let (user_id, group_id, _token) = setup_auth_with_group(&db);
    let raw_key = "sk_test-valid-key-1234";
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    make_setup_key(
        &db,
        user_id,
        group_id,
        raw_key,
        SetupKeyUsage::OneOff,
        expires_at,
    );

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "setup_key": raw_key,
        "agent_id": "agent-sk-test",
        "name": "SK Agent",
        "capabilities": [{"name": "compute"}]
    });
    let resp = client
        .post(format!("{base}/register-with-key"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["agent_card"]["name"], "SK Agent");
    assert!(
        result["api_token"].as_str().unwrap().starts_with("at_"),
        "api_token should start with at_"
    );
}

#[tokio::test]
async fn register_with_setup_key_invalid_key() {
    let (base, _db) = start_registry().await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "setup_key": "sk_totally-invalid-key",
        "agent_id": "agent-bad-key",
        "name": "Bad Key Agent",
        "capabilities": []
    });
    let resp = client
        .post(format!("{base}/register-with-key"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn register_with_setup_key_expired() {
    let (base, db) = start_registry().await;
    let (user_id, group_id, _token) = setup_auth_with_group(&db);
    let raw_key = "sk_test-expired-key";
    // expired 1 hour ago
    let expires_at = chrono::Utc::now() - chrono::Duration::hours(1);
    make_setup_key(
        &db,
        user_id,
        group_id,
        raw_key,
        SetupKeyUsage::OneOff,
        expires_at,
    );

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "setup_key": raw_key,
        "agent_id": "agent-expired",
        "name": "Expired Agent",
        "capabilities": []
    });
    let resp = client
        .post(format!("{base}/register-with-key"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn register_with_setup_key_oneoff_double_use() {
    let (base, db) = start_registry().await;
    let (user_id, group_id, _token) = setup_auth_with_group(&db);
    let raw_key = "sk_test-oneoff-double-use";
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    make_setup_key(
        &db,
        user_id,
        group_id,
        raw_key,
        SetupKeyUsage::OneOff,
        expires_at,
    );

    let client = reqwest::Client::new();

    // First use — should succeed.
    let body = serde_json::json!({
        "setup_key": raw_key,
        "agent_id": "agent-oneoff-1",
        "name": "OneOff Agent 1",
        "capabilities": []
    });
    let resp = client
        .post(format!("{base}/register-with-key"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Second use — must return 401.
    let body2 = serde_json::json!({
        "setup_key": raw_key,
        "agent_id": "agent-oneoff-2",
        "name": "OneOff Agent 2",
        "capabilities": []
    });
    let resp2 = client
        .post(format!("{base}/register-with-key"))
        .json(&body2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401);
}

// ── Key rotation lifecycle tests ──────────────────────────────────────────────

/// Helper: initiate a rotate-key request via HTTP and return the card_id string.
async fn rotate_key_http(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    old_kp: &AgentKeypair,
    new_kp: &AgentKeypair,
    card_id: &str,
) -> serde_json::Value {
    let card_uuid = AgentCardId::parse_str(card_id).expect("parse card_id");
    let proof = KeyRotationProof::new(old_kp, &new_kp.agent_id());
    let req = KeyRotationRequest {
        card_id: card_uuid,
        new_agent_id: new_kp.agent_id(),
        proof,
        grace_period_secs: None,
    };
    let resp = client
        .post(format!("{base}/agents/{card_id}/rotate-key"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "rotate-key failed");
    resp.json().await.unwrap()
}

/// Helper: complete a rotation via HTTP.
async fn complete_rotation_http(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    card_id: &str,
) -> serde_json::Value {
    let resp = client
        .post(format!("{base}/agents/{card_id}/complete-rotation"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "complete-rotation failed");
    resp.json().await.unwrap()
}

/// Full lifecycle: register → rotate → complete → verify ACL rewritten.
///
/// Covers:
/// - Agent with ACL rules as both source AND target.
/// - Agent with no ACL rules still completes successfully.
/// - Multiple ACL rules referencing the same agent.
#[tokio::test]
async fn rotate_and_complete_lifecycle() {
    let (base, db) = start_registry().await;
    let (user_id, _group_id, token) = setup_auth_with_group(&db);
    let client = reqwest::Client::new();

    // ── 1. Register two agents ────────────────────────────────────────────────
    let old_kp = AgentKeypair::generate();
    let peer_kp = AgentKeypair::generate();

    let reg_a = make_registration(old_kp.agent_id().as_str(), "Agent-A", &["compute"]);
    let reg_b = make_registration(peer_kp.agent_id().as_str(), "Agent-B", &["storage"]);

    let resp_a = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), 201);
    let card_a: serde_json::Value = resp_a.json().await.unwrap();
    let card_id_a = card_a["id"].as_str().unwrap().to_string();

    let resp_b = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), 201);

    // ── 2. Create ACL rules: A→B (source), B→A (target = A), A→B second rule ─
    //       After completion, all three must reference new_agent_id.
    let acl1 = serde_json::json!({
        "source": old_kp.agent_id().as_str(),
        "target": peer_kp.agent_id().as_str(),
        "allowed_capabilities": ["compute"]
    });
    let acl2 = serde_json::json!({
        "source": peer_kp.agent_id().as_str(),
        "target": old_kp.agent_id().as_str(),
        "allowed_capabilities": ["storage"]
    });
    // Second A→B rule (multiple rules referencing the same agent).
    let acl3 = serde_json::json!({
        "source": old_kp.agent_id().as_str(),
        "target": peer_kp.agent_id().as_str(),
        "allowed_capabilities": ["network"]
    });

    for acl in [&acl1, &acl2, &acl3] {
        let r = client
            .post(format!("{base}/acl"))
            .header("Authorization", format!("Bearer {token}"))
            .json(acl)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201, "ACL creation failed");
    }

    // ── 3. Initiate rotation ──────────────────────────────────────────────────
    let new_kp = AgentKeypair::generate();
    rotate_key_http(&client, &base, &token, &old_kp, &new_kp, &card_id_a).await;

    // During grace period, gate must accept both old and new agent_id.
    let gate_old = client
        .post(format!("{base}/gate/verify"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "agent_id": old_kp.agent_id().as_str(), "user_id": user_id.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        gate_old.status(),
        200,
        "gate should accept old agent_id during grace period"
    );

    let gate_new = client
        .post(format!("{base}/gate/verify"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "agent_id": new_kp.agent_id().as_str(), "user_id": user_id.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        gate_new.status(),
        200,
        "gate should accept new agent_id during grace period"
    );

    // ── 4. Complete rotation ──────────────────────────────────────────────────
    let result = complete_rotation_http(&client, &base, &token, &card_id_a).await;

    assert_eq!(
        result["old_agent_id"].as_str().unwrap(),
        old_kp.agent_id().as_str(),
    );
    assert_eq!(
        result["new_agent_id"].as_str().unwrap(),
        new_kp.agent_id().as_str(),
    );
    // 3 ACL rows touched: acl1 (source), acl2 (target), acl3 (source).
    assert_eq!(result["acl_rules_updated"].as_u64().unwrap(), 3);

    // ── 5. Verify agent card now shows new agent_id ───────────────────────────
    let card = client
        .get(format!("{base}/agents/{card_id_a}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(card.status(), 200);
    let card_json: serde_json::Value = card.json().await.unwrap();
    assert_eq!(
        card_json["agent_id"].as_str().unwrap(),
        new_kp.agent_id().as_str(),
        "agent_id must be updated to new key after completion"
    );

    // ── 6. Verify old_agent_id is in revocations ──────────────────────────────
    let revocations: Vec<serde_json::Value> = client
        .get(format!("{base}/revocations"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let revoked = revocations
        .iter()
        .any(|r| r["agent_id"].as_str() == Some(old_kp.agent_id().as_str()));
    assert!(
        revoked,
        "old agent_id must appear in revocations after completion"
    );

    // ── 7. Verify ACL rules reference new agent_id ────────────────────────────
    let acl_resp: Vec<serde_json::Value> = client
        .get(format!("{base}/acl"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    for rule in &acl_resp {
        assert_ne!(
            rule["source"].as_str().unwrap(),
            old_kp.agent_id().as_str(),
            "old agent_id must not appear as source in any ACL rule"
        );
        assert_ne!(
            rule["target"].as_str().unwrap(),
            old_kp.agent_id().as_str(),
            "old agent_id must not appear as target in any ACL rule"
        );
    }
}

/// Rotation completes successfully even when the agent has no ACL rules.
#[tokio::test]
async fn rotate_and_complete_no_acl_rules() {
    let (base, db) = start_registry().await;
    let (_user_id, _group_id, token) = setup_auth_with_group(&db);
    let client = reqwest::Client::new();

    let old_kp = AgentKeypair::generate();
    let reg = make_registration(old_kp.agent_id().as_str(), "Agent-No-ACL", &["compute"]);

    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let card: serde_json::Value = resp.json().await.unwrap();
    let card_id = card["id"].as_str().unwrap().to_string();

    let new_kp = AgentKeypair::generate();
    rotate_key_http(&client, &base, &token, &old_kp, &new_kp, &card_id).await;

    let result = complete_rotation_http(&client, &base, &token, &card_id).await;
    assert_eq!(result["acl_rules_updated"].as_u64().unwrap(), 0);
    assert_eq!(
        result["new_agent_id"].as_str().unwrap(),
        new_kp.agent_id().as_str()
    );
}

/// complete-rotation on a card with no pending rotation returns 409.
#[tokio::test]
async fn complete_rotation_without_pending_returns_conflict() {
    let (base, db) = start_registry().await;
    let (_user_id, _group_id, token) = setup_auth_with_group(&db);
    let client = reqwest::Client::new();

    let kp = AgentKeypair::generate();
    let reg = make_registration(kp.agent_id().as_str(), "Agent-No-Pending", &[]);

    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let card: serde_json::Value = resp.json().await.unwrap();
    let card_id = card["id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/agents/{card_id}/complete-rotation"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

/// complete-rotation by non-owner returns 403.
#[tokio::test]
async fn complete_rotation_wrong_owner_returns_forbidden() {
    let (base, db) = start_registry().await;
    let (_owner_id, _group_id, owner_token) = setup_auth_with_group(&db);
    let (_other_id, other_token) = setup_auth(&db);
    let client = reqwest::Client::new();

    let old_kp = AgentKeypair::generate();
    let reg = make_registration(old_kp.agent_id().as_str(), "Agent-Owner", &[]);

    let resp = client
        .post(format!("{base}/agents"))
        .header("Authorization", format!("Bearer {owner_token}"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let card: serde_json::Value = resp.json().await.unwrap();
    let card_id = card["id"].as_str().unwrap().to_string();

    let new_kp = AgentKeypair::generate();
    rotate_key_http(&client, &base, &owner_token, &old_kp, &new_kp, &card_id).await;

    // Other user tries to complete — must get 403.
    let resp = client
        .post(format!("{base}/agents/{card_id}/complete-rotation"))
        .header("Authorization", format!("Bearer {other_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
