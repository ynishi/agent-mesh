use agent_mesh_relay::{
    config::RelayConfig,
    gate::{HttpGateVerifier, NoopGateVerifier},
    hub::Hub,
    GateVerifier,
};
use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "relay", about = "Agent Mesh Relay Server")]
struct Cli {
    /// Path to config file (TOML).
    #[arg(short, long, default_value = "relay.toml")]
    config: String,

    /// Listen address (overrides config).
    #[arg(short, long)]
    listen: Option<String>,

    /// Data directory (overrides config).
    #[arg(short, long)]
    data_dir: Option<String>,

    /// Control Plane URL for gate verification (overrides config).
    #[arg(long)]
    cp_url: Option<String>,

    /// Bearer token for CP authentication (overrides config).
    #[arg(long)]
    cp_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = RelayConfig::load(&cli.config)?;

    // CLI overrides.
    if let Some(listen) = cli.listen {
        cfg.listen = listen;
    }
    if let Some(data_dir) = cli.data_dir {
        cfg.data_dir = data_dir.into();
    }
    if let Some(cp_url) = cli.cp_url {
        cfg.cp_url = Some(cp_url);
    }
    if let Some(cp_token) = cli.cp_token {
        cfg.cp_token = Some(cp_token);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| cfg.log_level.clone().into()),
        )
        .init();

    tracing::info!(?cfg, "relay starting");

    // Ensure data directory exists.
    std::fs::create_dir_all(&cfg.data_dir)?;

    let gate: Arc<dyn GateVerifier> = match (cfg.cp_url.as_deref(), cfg.cp_token.as_deref()) {
        (Some(url), Some(token)) => Arc::new(HttpGateVerifier::new(
            url.to_string(),
            token.to_string(),
            reqwest::Client::new(),
        )),
        _ => {
            tracing::warn!(
                "cp_url or cp_token not set, using NoopGateVerifier (all agents allowed)"
            );
            Arc::new(NoopGateVerifier)
        }
    };

    let hub = Arc::new(Hub::new(cfg.rate_limit, cfg.rate_burst, gate));
    hub.start_reaper();

    let app = agent_mesh_relay::app(Arc::clone(&hub));

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(listen = cfg.listen, "relay listening");

    // Graceful shutdown on SIGTERM/SIGINT.
    let shutdown_hub = Arc::clone(&hub);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received, closing connections");
            shutdown_hub.shutdown().await;
        })
        .await?;

    tracing::info!("relay stopped");
    Ok(())
}

/// Wait for SIGTERM or SIGINT.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {},
                    _ = sigterm.recv() => {},
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler, falling back to ctrl-c only");
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
