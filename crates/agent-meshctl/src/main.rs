use agent_meshctl::commands;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "meshctl", about = "Agent mesh control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new agent keypair.
    Keygen,
    /// Register an agent card with the registry.
    Register {
        /// Registry server URL.
        #[arg(long, default_value = "http://localhost:9801")]
        registry: String,
        /// Agent name.
        #[arg(long)]
        name: String,
        /// Agent description.
        #[arg(long)]
        description: Option<String>,
        /// Capabilities (comma-separated).
        #[arg(long)]
        capabilities: String,
        /// Secret key hex (or reads from MESH_SECRET_KEY env).
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Search for agents in the registry.
    Discover {
        /// Registry server URL.
        #[arg(long, default_value = "http://localhost:9801")]
        registry: String,
        /// Filter by capability name.
        #[arg(long)]
        capability: Option<String>,
        /// Search text.
        #[arg(long)]
        search: Option<String>,
    },
    /// Send a request to a remote agent through the relay.
    Request {
        /// Relay server WebSocket URL.
        #[arg(long, default_value = "ws://localhost:9800/ws")]
        relay: String,
        /// Target agent ID.
        #[arg(long)]
        target: String,
        /// Capability to invoke.
        #[arg(long)]
        capability: String,
        /// JSON payload.
        #[arg(long, default_value = "{}")]
        payload: String,
        /// Secret key hex (or reads from MESH_SECRET_KEY env).
        #[arg(long)]
        secret_key: Option<String>,
        /// Timeout in seconds.
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Show relay status (connected agents, buffers, revocations).
    Status {
        /// Relay server HTTP URL.
        #[arg(long, default_value = "http://localhost:9800")]
        relay: String,
    },
    /// Revoke an agent's key. The agent will be disconnected and blocked.
    Revoke {
        /// Relay server HTTP URL.
        #[arg(long, default_value = "http://localhost:9800")]
        relay: String,
        /// Reason for revocation.
        #[arg(long)]
        reason: Option<String>,
        /// Secret key hex (or reads from MESH_SECRET_KEY env).
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Add an ACL rule (outputs JSON to stdout for inclusion in meshd config).
    Acl {
        /// Source agent ID.
        #[arg(long)]
        source: String,
        /// Target agent ID.
        #[arg(long)]
        target: String,
        /// Allowed capabilities (comma-separated).
        #[arg(long)]
        allow: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => commands::keygen(),
        Commands::Register {
            registry,
            name,
            description,
            capabilities,
            secret_key,
        } => {
            commands::register(
                &registry,
                &name,
                description.as_deref(),
                &capabilities,
                secret_key.as_deref(),
            )
            .await
        }
        Commands::Discover {
            registry,
            capability,
            search,
        } => commands::discover(&registry, capability.as_deref(), search.as_deref()).await,
        Commands::Request {
            relay,
            target,
            capability,
            payload,
            secret_key,
            timeout,
        } => {
            commands::request(
                &relay,
                &target,
                &capability,
                &payload,
                secret_key.as_deref(),
                timeout,
            )
            .await
        }
        Commands::Status { relay } => commands::status(&relay).await,
        Commands::Revoke {
            relay,
            reason,
            secret_key,
        } => commands::revoke(&relay, reason.as_deref(), secret_key.as_deref()).await,
        Commands::Acl {
            source,
            target,
            allow,
        } => commands::acl(&source, &target, &allow),
    }
}
