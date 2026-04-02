use agent_meshctl::{commands, daemon};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "meshctl", about = "Agent mesh control CLI")]
struct Cli {
    /// meshd socket path (default: ~/.mesh/meshd.sock)
    #[arg(long)]
    meshd: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new agent keypair.
    Keygen,
    /// Log in to the control plane via OAuth Device Flow.
    Login {
        /// Control plane URL.
        #[arg(long)]
        cp_url: String,
    },
    /// Register an agent card with the registry.
    Register {
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
    /// Show meshd connection status.
    Status,
    /// Revoke an agent's key. The agent will be disconnected and blocked.
    Revoke {
        /// Reason for revocation.
        #[arg(long)]
        reason: Option<String>,
        /// Secret key hex (or reads from MESH_SECRET_KEY env).
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Manage agent groups.
    Group {
        #[command(subcommand)]
        subcommand: GroupCommands,
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

#[derive(Subcommand)]
enum GroupCommands {
    /// Create a new group.
    Create {
        /// Group name.
        #[arg(long)]
        name: String,
    },
    /// List all groups.
    List,
    /// Add a member to a group.
    AddMember {
        /// Group ID.
        #[arg(long)]
        group_id: String,
        /// User ID to add.
        #[arg(long)]
        user_id: String,
    },
    /// Remove a member from a group.
    RemoveMember {
        /// Group ID.
        #[arg(long)]
        group_id: String,
        /// User ID to remove.
        #[arg(long)]
        user_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();
    let sock_path = cli.meshd.map(PathBuf::from);

    match cli.command {
        Commands::Keygen => commands::keygen(),
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
        Commands::Acl {
            source,
            target,
            allow,
        } => commands::acl(&source, &target, &allow),
        _ => {
            let client = daemon::ensure_meshd(sock_path).await?;
            match cli.command {
                Commands::Login { cp_url } => commands::login(&client, &cp_url).await,
                Commands::Register {
                    name,
                    description,
                    capabilities,
                    secret_key,
                } => {
                    commands::register(
                        &client,
                        &name,
                        description.as_deref(),
                        &capabilities,
                        secret_key.as_deref(),
                    )
                    .await
                }
                Commands::Discover { capability, search } => {
                    commands::discover(&client, capability.as_deref(), search.as_deref()).await
                }
                Commands::Status => commands::status(&client).await,
                Commands::Revoke { reason, secret_key } => {
                    commands::revoke(&client, reason.as_deref(), secret_key.as_deref()).await
                }
                Commands::Group { subcommand } => match subcommand {
                    GroupCommands::Create { name } => commands::group_create(&client, &name).await,
                    GroupCommands::List => commands::group_list(&client).await,
                    GroupCommands::AddMember { group_id, user_id } => {
                        commands::group_add_member(&client, &group_id, &user_id).await
                    }
                    GroupCommands::RemoveMember { group_id, user_id } => {
                        commands::group_remove_member(&client, &group_id, &user_id).await
                    }
                },
                // Already handled above
                Commands::Keygen | Commands::Request { .. } | Commands::Acl { .. } => {
                    unreachable!()
                }
            }
        }
    }
}
