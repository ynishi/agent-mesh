use std::sync::Arc;

use agent_mesh_core::identity::{AgentId, GroupId};
use agent_mesh_registry::db::Database;
use agent_mesh_relay::hub::Hub;
use agent_mesh_relay::GateVerifier;
use async_trait::async_trait;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "agent-mesh-server",
    about = "All-in-one agent-mesh server (registry + relay)"
)]
struct Cli {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
    /// SQLite database path.
    #[arg(long, default_value = "mesh.db")]
    db_path: String,
    /// OAuth provider name (e.g. "github"). Required together with --oauth-client-id and --oauth-client-secret.
    #[arg(long, env = "OAUTH_PROVIDER")]
    oauth_provider: Option<String>,
    /// OAuth client ID.
    #[arg(long, env = "OAUTH_CLIENT_ID")]
    oauth_client_id: Option<String>,
    /// OAuth client secret.
    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    oauth_client_secret: Option<String>,
}

/// In-process gate verifier: resolves agent_id → group_id via direct DB access.
/// Avoids HTTP round-trips inside the same process.
pub struct InProcessGateVerifier {
    db: Arc<Database>,
}

#[async_trait]
impl GateVerifier for InProcessGateVerifier {
    async fn verify_agent(&self, agent_id: &AgentId) -> anyhow::Result<Option<GroupId>> {
        match self.db.get_agent_group_id(agent_id.as_str())? {
            Some(gid) => Ok(Some(gid)),
            None => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    // 1. Open database.
    let db = Arc::new(Database::open(&cli.db_path)?);

    // 2. Build OAuthConfig if all three args are provided.
    let oauth_config = match (
        cli.oauth_provider,
        cli.oauth_client_id,
        cli.oauth_client_secret,
    ) {
        (Some(provider), Some(client_id), Some(client_secret)) => Some(
            agent_mesh_registry::OAuthConfig::from_provider(provider, client_id, client_secret)?,
        ),
        _ => None,
    };

    // 3. Build registry AppState.
    let sync_hub = Arc::new(agent_mesh_registry::sync::SyncHub::new());
    let cp_state = agent_mesh_registry::AppState {
        db: Arc::clone(&db),
        sync_hub: Arc::clone(&sync_hub),
        oauth_config,
        http_client: reqwest::Client::new(),
    };

    // 4. Build relay Hub with InProcessGateVerifier.
    let gate: Arc<dyn GateVerifier> = Arc::new(InProcessGateVerifier {
        db: Arc::clone(&db),
    });
    let hub = Arc::new(Hub::new(50.0, 100.0, gate));
    hub.start_reaper();

    // 5. Combine routers: relay under /relay prefix, registry at root.
    let cp_router = agent_mesh_registry::app(cp_state);
    let relay_router = agent_mesh_relay::app(Arc::clone(&hub));

    let app = axum::Router::new()
        .nest("/relay", relay_router)
        .merge(cp_router);

    // 6. Start server.
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(addr = %cli.listen, "agent-mesh-server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
