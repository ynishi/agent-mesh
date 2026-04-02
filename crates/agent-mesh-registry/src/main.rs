use agent_mesh_registry::db::Database;
use agent_mesh_registry::{AppState, OAuthConfig};
use anyhow::{bail, Result};
use clap::Parser;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "registry", about = "Agent Mesh Registry Server")]
struct Cli {
    /// Listen address (host:port). Env: REGISTRY_ADDR
    #[arg(short, long, default_value = "0.0.0.0:9801")]
    listen: String,

    /// SQLite database path. Env: REGISTRY_DB
    #[arg(short, long, default_value = "registry.db")]
    db: String,

    /// OAuth provider (e.g. "github"). If not set, OAuth endpoints are disabled.
    #[arg(long)]
    oauth_provider: Option<String>,

    /// OAuth client ID
    #[arg(long)]
    oauth_client_id: Option<String>,

    /// OAuth client secret
    #[arg(long)]
    oauth_client_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    // CLI args take precedence over env vars.
    let db_path = if cli.db != "registry.db" {
        cli.db
    } else {
        std::env::var("REGISTRY_DB").unwrap_or(cli.db)
    };

    let addr = if cli.listen != "0.0.0.0:9801" {
        cli.listen
    } else {
        std::env::var("REGISTRY_ADDR").unwrap_or(cli.listen)
    };

    // Build OAuthConfig only when all three args are provided.
    let oauth_config =
        match (
            cli.oauth_provider,
            cli.oauth_client_id,
            cli.oauth_client_secret,
        ) {
            (Some(provider), Some(client_id), Some(client_secret)) => Some(
                OAuthConfig::from_provider(provider, client_id, client_secret)?,
            ),
            (None, None, None) => None,
            _ => bail!(
                "OAuth configuration is incomplete: --oauth-provider, --oauth-client-id, \
             and --oauth-client-secret must all be provided together"
            ),
        };

    let db = Arc::new(Database::open(&db_path)?);
    let state = AppState {
        db,
        oauth_config,
        http_client: reqwest::Client::new(),
    };

    let app = agent_mesh_registry::app(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("registry listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
