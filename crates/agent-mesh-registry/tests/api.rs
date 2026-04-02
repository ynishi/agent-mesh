use std::future::IntoFuture;
use std::sync::Arc;

use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::{AgentKeypair, UserId};
use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};
use agent_mesh_registry::auth::hash_token;
use agent_mesh_registry::db::Database;
use agent_mesh_registry::AppState;

async fn start_registry() -> (String, Arc<Database>) {
    let db = Arc::new(Database::open(":memory:").expect("in-memory db"));
    let state = AppState {
        db: db.clone(),
        oauth_config: None,
        http_client: reqwest::Client::new(),
    };
    let app = agent_mesh_registry::app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    (format!("http://127.0.0.1:{}", addr.port()), db)
}

/// Create a test user, group, and API token. Returns (user_id, raw_token).
fn setup_auth(db: &Arc<Database>) -> (UserId, String) {
    let user = User {
        id: UserId::new_v4(),
        external_id: format!("test-user-{}", uuid::Uuid::new_v4()),
        provider: "test".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: chrono::Utc::now(),
    };
    db.create_user(&user).expect("create test user");

    let group = Group {
        id: agent_mesh_core::identity::GroupId::new_v4(),
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

    let raw_token = format!("test-token-{}", uuid::Uuid::new_v4());
    let token = ApiToken {
        token_hash: hash_token(&raw_token),
        user_id: user.id,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    db.create_api_token(&token).expect("create api token");

    (user.id, raw_token)
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
