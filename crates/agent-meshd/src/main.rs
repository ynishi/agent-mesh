use agent_meshd::config::NodeConfig;
use agent_meshd::node::MeshNode;
use anyhow::{bail, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "meshd", about = "Agent mesh node daemon")]
struct Cli {
    /// Path to node configuration file (JSON). When provided, CLI args override config values.
    #[arg(short, long)]
    config: Option<String>,

    /// Relay server WebSocket URL.
    #[arg(short, long)]
    relay: Option<String>,

    /// Local agent HTTP endpoint to proxy requests to.
    #[arg(short = 'a', long)]
    local_agent: Option<String>,

    /// Ed25519 secret key (hex). Env: MESH_SECRET_KEY
    #[arg(short, long)]
    secret_key: Option<String>,

    /// ACL policy file (JSON).
    #[arg(long)]
    acl: Option<String>,

    /// Control Plane URL (e.g., "http://localhost:9801").
    #[arg(long)]
    cp_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let cfg = NodeConfig::from_cli(
        cli.config.as_deref(),
        cli.relay.as_deref(),
        cli.local_agent.as_deref(),
        cli.secret_key
            .as_deref()
            .or(std::env::var("MESH_SECRET_KEY").ok().as_deref()),
        cli.acl.as_deref(),
        cli.cp_url.as_deref(),
    )?;

    if cfg.relay_url.is_empty() {
        bail!("--relay is required (or set relay_url in config file)");
    }
    if cfg.local_agent_url.is_empty() {
        bail!("--local-agent is required (or set local_agent_url in config file)");
    }
    if cfg.secret_key_hex.is_empty() {
        bail!("--secret-key is required (or set secret_key_hex in config file, or MESH_SECRET_KEY env)");
    }

    tracing::info!(agent = cfg.agent_id_display(), relay = %cfg.relay_url, "starting meshd");

    let node = MeshNode::new(cfg)?;
    node.run().await
}
