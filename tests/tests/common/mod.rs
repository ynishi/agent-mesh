use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::agent_card::AgentCardRegistration;
use agent_mesh_core::identity::{AgentId, AgentKeypair, GroupId, UserId};
use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};
use agent_mesh_registry::auth::hash_token;
use agent_mesh_registry::db::Database;
use agent_mesh_registry::sync::SyncHub;
use agent_mesh_registry::AppState;
use agent_mesh_relay::gate::NoopGateVerifier;
use agent_mesh_relay::hub::Hub;
use agent_mesh_sdk::ValueStream;
use agent_mesh_sdk::{CancelToken, RequestHandler};
use agent_meshctl::daemon::MeshdClient;
use agent_meshd::config::NodeConfig;
use agent_meshd::node::MeshNode;
use anyhow::Result;
use tempfile::TempDir;

/// Start a relay on a random port and return `(ws_url, http_base_url)`.
pub async fn start_relay() -> (String, String) {
    let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
    let app = agent_mesh_relay::app(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay listener");
    let addr = listener.local_addr().expect("relay local_addr");
    tokio::spawn(axum::serve(listener, app).into_future());
    (
        format!("ws://127.0.0.1:{}/ws", addr.port()),
        format!("http://127.0.0.1:{}", addr.port()),
    )
}

/// Start a `MeshNode` in a temp directory and return `(JoinHandle, UDS socket path, TempDir)`.
///
/// The caller must keep `TempDir` alive for the duration of the test.
/// Call `handle.abort()` to stop meshd when done.
pub async fn start_meshd(
    relay_url: &str,
    local_agent_url: &str,
) -> Result<(tokio::task::JoinHandle<()>, PathBuf, TempDir)> {
    let kp = AgentKeypair::generate();
    let secret_hex = hex::encode(kp.secret_bytes());

    // macOS UDS path limit: 104 bytes.
    // tempdir_in("/tmp") produces short paths like /tmp/.tmpXXXXXX/
    let tmp = tempfile::tempdir_in("/tmp")?;
    let sock_path = tmp.path().join("meshd.sock");

    let cfg = NodeConfig {
        secret_key_hex: secret_hex,
        relay_url: relay_url.to_string(),
        local_agent_url: local_agent_url.to_string(),
        acl: allow_all_acl(),
        config_path: None,
        cp_url: None,
        bearer_token: None,
    };

    let node = MeshNode::new_with_mesh_dir(cfg, tmp.path())?;
    let handle = tokio::spawn(async move {
        if let Err(e) = node.run().await {
            tracing::error!("meshd exited with error: {e}");
        }
    });

    wait_meshd_ready(&sock_path).await?;

    Ok((handle, sock_path, tmp))
}

/// Poll the UDS socket until meshd responds to `GET /status` or timeout (5 seconds).
pub async fn wait_meshd_ready(sock_path: &std::path::Path) -> Result<()> {
    let client = MeshdClient::new(sock_path.to_path_buf());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if client.is_alive().await {
            // Give relay_loop a moment to complete WS authentication.
            tokio::time::sleep(Duration::from_millis(200)).await;
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "meshd did not become ready within 5 seconds (socket: {})",
                sock_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Simple echo handler: returns `{"echo": <payload>, "from": "<agent_id>"}`.
pub struct EchoHandler;

#[async_trait::async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(
        &self,
        from: &AgentId,
        payload: &serde_json::Value,
        _cancel: CancelToken,
    ) -> serde_json::Value {
        serde_json::json!({
            "echo": payload,
            "from": from.as_str(),
        })
    }
}

/// ACL policy that allows all requests.
pub fn allow_all_acl() -> AclPolicy {
    AclPolicy {
        default_deny: false,
        rules: vec![],
    }
}

/// ACL policy that denies all requests.
pub fn deny_all_acl() -> AclPolicy {
    AclPolicy {
        default_deny: true,
        rules: vec![],
    }
}

// ── Registry helpers ─────────────────────────────────────────────────────────

/// Start a Registry in-process on a random port.
///
/// Returns `(registry_url, raw_bearer_token, Arc<Database>, Arc<SyncHub>, user_id, group_id)`.
///
/// The database is seeded with one test user, one group, and one API token.
/// The caller keeps the `Arc<Database>` alive and can use it to register agents
/// or perform other direct DB operations.
/// The caller may also hold `Arc<SyncHub>` to manually broadcast SyncEvents in tests.
pub async fn start_registry() -> (String, String, Arc<Database>, Arc<SyncHub>, UserId, GroupId) {
    let db = Database::open(":memory:").expect("in-memory registry db");
    let db = Arc::new(db);

    // Create test user.
    let user_id = UserId::new_v4();
    let user = User {
        id: user_id,
        external_id: format!("test-{}", user_id),
        provider: "test".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: chrono::Utc::now(),
    };
    db.create_user(&user).expect("create test user");

    // Create test group.
    let group_id = GroupId::new_v4();
    let group = Group {
        id: group_id,
        name: "test-group".to_string(),
        created_by: user_id,
        created_at: chrono::Utc::now(),
    };
    db.create_group(&group).expect("create test group");
    db.add_group_member(&GroupMember {
        group_id,
        user_id,
        role: GroupRole::Owner,
    })
    .expect("add group member");

    // Create API token.
    let raw_token = format!("test-token-{}", uuid::Uuid::new_v4());
    let token = ApiToken {
        token_hash: hash_token(&raw_token),
        user_id,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    db.create_api_token(&token).expect("create api token");

    // Build and serve Registry app.
    let sync_hub = Arc::new(SyncHub::new());
    let state = AppState {
        db: Arc::clone(&db),
        oauth_config: None,
        http_client: reqwest::Client::new(),
        sync_hub: Arc::clone(&sync_hub),
    };
    let app = agent_mesh_registry::app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind registry listener");
    let addr = listener.local_addr().expect("registry local_addr");
    tokio::spawn(axum::serve(listener, app).into_future());

    let registry_url = format!("http://127.0.0.1:{}", addr.port());
    (registry_url, raw_token, db, sync_hub, user_id, group_id)
}

/// Start a `MeshNode` with CP URL and bearer token.
///
/// Returns `(JoinHandle, UDS socket path, TempDir, AgentId)`.
/// `agent_id` is derived from the generated keypair so callers can pre-register it in Registry.
pub async fn start_meshd_with_cp(
    relay_url: &str,
    cp_url: &str,
    bearer_token: &str,
) -> Result<(tokio::task::JoinHandle<()>, PathBuf, TempDir, AgentId)> {
    let kp = AgentKeypair::generate();
    let agent_id = kp.agent_id();
    let secret_hex = hex::encode(kp.secret_bytes());

    let tmp = tempfile::tempdir_in("/tmp")?;
    let sock_path = tmp.path().join("meshd.sock");

    let cfg = NodeConfig {
        secret_key_hex: secret_hex,
        relay_url: relay_url.to_string(),
        local_agent_url: "".to_string(),
        acl: allow_all_acl(),
        config_path: None,
        cp_url: Some(cp_url.to_string()),
        bearer_token: Some(bearer_token.to_string()),
    };

    let node = MeshNode::new_with_mesh_dir(cfg, tmp.path())?;
    let handle = tokio::spawn(async move {
        if let Err(e) = node.run().await {
            tracing::error!("meshd (cp) exited with error: {e}");
        }
    });

    wait_meshd_ready(&sock_path).await?;

    Ok((handle, sock_path, tmp, agent_id))
}

/// Register a test AgentCard directly in the Registry DB.
pub fn register_test_agent(
    db: &Database,
    owner_id: UserId,
    group_id: GroupId,
    agent_id: &AgentId,
    name: &str,
) -> agent_mesh_core::agent_card::AgentCard {
    let reg = AgentCardRegistration {
        agent_id: agent_id.clone(),
        name: name.to_string(),
        description: None,
        capabilities: vec![],
        metadata: None,
    };
    db.register(&reg, owner_id, group_id)
        .expect("register test agent")
}

/// Poll meshd `/status` until the node state is "Syncing" (or better) or timeout.
pub async fn wait_meshd_syncing(sock_path: &std::path::Path) -> Result<()> {
    let client = MeshdClient::new(sock_path.to_path_buf());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok((status, body)) = client.get("/status").await {
            if status.is_success() {
                let state = body["state"].as_str().unwrap_or("");
                if state == "Syncing" || state == "Connected" {
                    return Ok(());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "meshd did not reach Syncing state within 15 seconds (socket: {})",
                sock_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll meshd `/status` until `peers_count > 0` or timeout.
pub async fn wait_peers_populated(sock_path: &std::path::Path) -> Result<()> {
    let client = MeshdClient::new(sock_path.to_path_buf());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok((status, body)) = client.get("/status").await {
            if status.is_success() {
                let peers = body["peers_count"].as_u64().unwrap_or(0);
                if peers > 0 {
                    return Ok(());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "meshd peers_count did not become > 0 within 15 seconds (socket: {})",
                sock_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ── Relay re-connection helpers ───────────────────────────────────────────────

/// Start a relay on a random port and return `(ws_url, http_base_url, JoinHandle, SocketAddr)`.
///
/// The `JoinHandle` can be aborted to stop the relay (simulating relay crash).
/// `SocketAddr` is needed to restart the relay on the same address.
pub async fn start_relay_with_handle() -> (
    String,
    String,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
    SocketAddr,
) {
    let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
    let app = agent_mesh_relay::app(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay listener");
    let addr = listener.local_addr().expect("relay local_addr");
    let handle = tokio::spawn(axum::serve(listener, app).into_future());
    (
        format!("ws://127.0.0.1:{}/ws", addr.port()),
        format!("http://127.0.0.1:{}", addr.port()),
        handle,
        addr,
    )
}

/// Start a relay on the specified `SocketAddr` and return `(ws_url, http_base_url, JoinHandle)`.
///
/// Used to restart a relay on the same port after it was aborted.
/// On macOS, the caller may need a short sleep before calling this if the
/// previous listener was just aborted.
/// Panics if bind fails; callers that need retry logic should use
/// `TcpListener::bind` directly.
#[allow(dead_code)]
pub async fn start_relay_on_addr(
    addr: SocketAddr,
) -> (
    String,
    String,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
) {
    let hub = Arc::new(Hub::new(100.0, 200.0, Arc::new(NoopGateVerifier)));
    let app = agent_mesh_relay::app(hub);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("re-bind relay listener");
    let handle = tokio::spawn(axum::serve(listener, app).into_future());
    (
        format!("ws://127.0.0.1:{}/ws", addr.port()),
        format!("http://127.0.0.1:{}", addr.port()),
        handle,
    )
}

// ── Streaming handler ─────────────────────────────────────────────────────────

/// A `RequestHandler` that returns multiple chunks from `handle_stream`.
///
/// `handle()` returns a simple JSON object; `handle_stream()` yields
/// `chunk_count` chunks each containing `{"chunk": i, "total": chunk_count}`.
pub struct StreamingHandler {
    pub chunk_count: usize,
}

#[async_trait::async_trait]
impl RequestHandler for StreamingHandler {
    async fn handle(
        &self,
        from: &AgentId,
        _payload: &serde_json::Value,
        _cancel: CancelToken,
    ) -> serde_json::Value {
        serde_json::json!({"streaming": false, "from": from.as_str()})
    }

    async fn handle_stream(
        &self,
        _from: &AgentId,
        _payload: &serde_json::Value,
        _cancel: CancelToken,
    ) -> ValueStream {
        let count = self.chunk_count;
        let stream = futures_util::stream::iter(
            (0..count).map(move |i| serde_json::json!({"chunk": i, "total": count})),
        );
        Box::pin(stream)
    }
}
