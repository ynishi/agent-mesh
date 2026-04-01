use std::future::IntoFuture;
use std::sync::Arc;

use agent_mesh_core::agent_card::{AgentCardRegistration, Capability};
use agent_mesh_core::identity::AgentKeypair;
use agent_mesh_registry::db::Database;
use agent_mesh_registry::AppState;

async fn start_registry() -> String {
    let db = Arc::new(Database::open(":memory:").expect("in-memory db"));
    let state = AppState {
        db,
        relay_url: None,
    };
    let app = agent_mesh_registry::app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    format!("http://127.0.0.1:{}", addr.port())
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

#[tokio::test]
async fn health_check() {
    let base = start_registry().await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn register_agent_card() {
    let base = start_registry().await;
    let client = reqwest::Client::new();

    let kp = AgentKeypair::generate();
    let reg = make_registration(
        kp.agent_id().as_str(),
        "Bob",
        &["scheduling", "availability"],
    );

    let resp = client
        .post(format!("{base}/agents"))
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
    let base = start_registry().await;
    let client = reqwest::Client::new();

    // Register two agents with different capabilities.
    let reg1 = make_registration("agent-1", "Alice", &["scheduling", "contact"]);
    let reg2 = make_registration("agent-2", "Bob", &["billing"]);

    client
        .post(format!("{base}/agents"))
        .json(&reg1)
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/agents"))
        .json(&reg2)
        .send()
        .await
        .unwrap();

    // Search for scheduling — only Alice.
    let resp = client
        .get(format!("{base}/agents?capability=scheduling"))
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
    let base = start_registry().await;
    let client = reqwest::Client::new();

    let reg1 = make_registration("agent-1", "Alice", &["scheduling"]);
    let reg2 = make_registration("agent-2", "Bob", &["billing"]);

    client
        .post(format!("{base}/agents"))
        .json(&reg1)
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/agents"))
        .json(&reg2)
        .send()
        .await
        .unwrap();

    let resp = client.get(format!("{base}/agents")).send().await.unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 2);
}

#[tokio::test]
async fn get_agent_by_id() {
    let base = start_registry().await;
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let resp = client
        .get(format!("{base}/agents/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fetched["name"], "Alice");
}

#[tokio::test]
async fn get_agent_not_found() {
    let base = start_registry().await;
    let resp = reqwest::get(format!(
        "{base}/agents/00000000-0000-0000-0000-000000000000"
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn update_agent_card() {
    let base = start_registry().await;
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let updated_reg = make_registration("agent-1", "Alice v2", &["scheduling", "contact"]);
    let resp = client
        .put(format!("{base}/agents/{id}"))
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
    let base = start_registry().await;
    let client = reqwest::Client::new();

    let reg = make_registration("agent-1", "Alice", &["scheduling"]);
    let resp = client
        .post(format!("{base}/agents"))
        .json(&reg)
        .send()
        .await
        .unwrap();
    let card: serde_json::Value = resp.json().await.unwrap();
    let id = card["id"].as_str().unwrap();

    let resp = client
        .delete(format!("{base}/agents/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Confirm gone.
    let resp = client
        .get(format!("{base}/agents/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
