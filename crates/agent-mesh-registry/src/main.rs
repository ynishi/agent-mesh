use agent_mesh_registry::db::Database;
use agent_mesh_registry::AppState;
use anyhow::Result;
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

    /// Relay URL for liveness enrichment (optional). Env: RELAY_URL
    #[arg(long)]
    relay_url: Option<String>,
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

    let relay_url = cli.relay_url.or_else(|| std::env::var("RELAY_URL").ok());

    if let Some(ref url) = relay_url {
        tracing::info!(relay = %url, "liveness enrichment enabled");
    }

    let addr = if cli.listen != "0.0.0.0:9801" {
        cli.listen
    } else {
        std::env::var("REGISTRY_ADDR").unwrap_or(cli.listen)
    };

    let db = Arc::new(Database::open(&db_path)?);
    let state = AppState { db, relay_url };

    let app = agent_mesh_registry::app(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("registry listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
