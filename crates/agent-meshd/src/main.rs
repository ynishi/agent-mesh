mod config;
mod node;
mod proxy;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "meshd", about = "Agent mesh node daemon")]
struct Cli {
    /// Path to the node configuration file.
    #[arg(short, long, default_value = "meshd.json")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let cfg = config::NodeConfig::load(&cli.config)?;
    tracing::info!(agent = cfg.agent_id_display(), relay = %cfg.relay_url, "starting meshd");

    let node = node::MeshNode::new(cfg)?;
    node.run().await
}
