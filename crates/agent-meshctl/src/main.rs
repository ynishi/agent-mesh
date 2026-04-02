use agent_meshctl::{commands, daemon};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
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
    /// Manage setup keys for non-interactive agent registration.
    SetupKey {
        #[command(subcommand)]
        subcommand: SetupKeyCommands,
    },
    /// Register an agent using a setup key.
    ///
    /// Sends a registration request to meshd, which proxies it to the Control Plane.
    /// On success, saves the issued API token to ~/.mesh/config.toml.
    /// CP/Relay connection is NOT started automatically (out of scope for this command).
    Up {
        /// Setup key (or reads from MESH_SETUP_KEY env).
        #[arg(long)]
        setup_key: Option<String>,
        /// Agent name.
        #[arg(long)]
        name: String,
        /// Capabilities (comma-separated).
        #[arg(long)]
        capabilities: String,
        /// Secret key hex (or reads from MESH_SECRET_KEY env).
        #[arg(long)]
        secret_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SetupKeyCommands {
    /// Create a new setup key for non-interactive agent registration.
    Create {
        /// Group ID to scope the setup key to.
        #[arg(long)]
        group_id: String,
        /// Key usage: "one-off" (single use) or "reusable".
        #[arg(long, default_value = "one-off")]
        usage: String,
        /// Maximum number of uses (for reusable keys).
        #[arg(long)]
        max_uses: Option<u32>,
        /// Validity in hours from now.
        #[arg(long, default_value = "24")]
        expires_in_hours: u64,
    },
    /// List all setup keys.
    List,
    /// Revoke a setup key by ID.
    Revoke {
        /// Setup key ID to revoke.
        #[arg(long)]
        id: String,
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
                Commands::SetupKey { subcommand } => match subcommand {
                    SetupKeyCommands::Create {
                        group_id,
                        usage,
                        max_uses,
                        expires_in_hours,
                    } => {
                        commands::setup_key_create(
                            &client,
                            &group_id,
                            &usage,
                            max_uses,
                            expires_in_hours,
                        )
                        .await
                    }
                    SetupKeyCommands::List => commands::setup_key_list(&client).await,
                    SetupKeyCommands::Revoke { id } => {
                        commands::setup_key_revoke(&client, &id).await
                    }
                },
                Commands::Up {
                    setup_key,
                    name,
                    capabilities,
                    secret_key,
                } => up_with_setup_key(&client, setup_key, &name, &capabilities, secret_key).await,
                // Already handled above
                Commands::Keygen | Commands::Request { .. } | Commands::Acl { .. } => {
                    unreachable!()
                }
            }
        }
    }
}

/// Minimal credentials structure for saving to ~/.mesh/config.toml.
#[derive(Debug, Serialize, Deserialize, Default)]
struct MeshCredentials {
    bearer_token: Option<String>,
    cp_url: Option<String>,
}

impl MeshCredentials {
    fn save(&self, mesh_dir: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(mesh_dir)
            .with_context(|| format!("failed to create dir {}", mesh_dir.display()))?;
        let path = mesh_dir.join("config.toml");
        let content = toml::to_string(self).context("failed to serialize credentials")?;
        std::fs::write(&path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }

        Ok(())
    }
}

/// Registers an agent using a setup key and saves the issued API token.
///
/// CP/Relay connection is not started (out of scope for this command).
async fn up_with_setup_key(
    client: &daemon::MeshdClient,
    setup_key_arg: Option<String>,
    name: &str,
    capabilities_csv: &str,
    secret_key_arg: Option<String>,
) -> Result<()> {
    // 1. Resolve setup key.
    let setup_key = match setup_key_arg {
        Some(k) => k,
        None => std::env::var("MESH_SETUP_KEY")
            .context("no --setup-key provided and MESH_SETUP_KEY env not set")?,
    };

    // 2. Resolve secret key and derive agent_id.
    let keypair = commands::resolve_secret_key(secret_key_arg.as_deref())?;
    let agent_id = keypair.agent_id().to_string();

    // 3. Build capabilities list.
    let caps: Vec<serde_json::Value> = capabilities_csv
        .split(',')
        .map(|s| serde_json::json!({ "name": s.trim() }))
        .collect();

    // 4. POST /register-with-key via meshd.
    let body = serde_json::json!({
        "setup_key": setup_key,
        "agent_id": agent_id,
        "name": name,
        "capabilities": caps,
    });

    let (status, resp) = client.post("/register-with-key", &body).await?;

    if !status.is_success() {
        anyhow::bail!("Registration failed ({}): {}", status, resp);
    }

    // 5. Extract api_token from response.
    let api_token = resp
        .get("api_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("api_token missing from response: {resp}"))?
        .to_string();

    let cp_url = resp
        .get("cp_url")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // 6. Resolve mesh_dir from socket path parent.
    let sock_path = daemon::MeshdClient::default_sock_path()?;
    let mesh_dir = sock_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine mesh_dir from socket path"))?;

    // 7. Save credentials.
    let creds = MeshCredentials {
        bearer_token: Some(api_token),
        cp_url,
    };
    creds.save(mesh_dir)?;

    println!("Registered successfully. Token saved.");
    Ok(())
}
