//! CLI for operating an agent-mesh identity: keygen, register, discover,
//! request, revoke, and (optionally) an MCP adapter for driving the mesh
//! from an MCP client.
//!
//! # Architecture
//!
//! `agent-meshctl` is the human/tool-facing entry point to the mesh. It
//! talks to the control plane directly for account-level operations and to
//! a locally running `agent-meshd` for anything that needs an active mesh
//! session (request/discover through the daemon rather than re-implementing
//! relay connectivity in the CLI).
//!
//! - [`commands`] — one module per subcommand (`keygen`, `login`,
//!   `register`, `deregister`, `discover`, `request`, `status`, `rotate`,
//!   `revoke`, `acl`, `group`, `setup_key`), each a thin `clap` handler.
//! - [`cp_client`] — direct HTTP client for the control plane
//!   (`agent-mesh-registry`), used by commands that don't need meshd
//!   (login, register, discover). Reads credentials from
//!   `~/.mesh/config.toml`.
//! - [`daemon`] — [`daemon::MeshdClient`] and [`daemon::ensure_meshd`]: locates
//!   or spawns a local `agent-meshd` process and talks to it over its local
//!   API for request/discover operations that need an active mesh session.
//! - [`mcp_server`] (behind the `mcp-server` feature) — exposes mesh
//!   request/reply as MCP tools via `rmcp`; [`mcp_server::inbound`] queues
//!   incoming mesh requests forwarded by meshd until an MCP client replies.
//!
//! This crate depends on `agent-mesh-core` for identity/crypto types only —
//! it does not link `agent-mesh-sdk`, `agent-mesh-relay`, or
//! `agent-mesh-registry`; it reaches the registry over plain HTTP
//! ([`cp_client`]) and meshd over its local HTTP API ([`daemon`]).
pub mod commands;
pub mod cp_client;
pub mod daemon;
#[cfg(feature = "mcp-server")]
pub mod mcp_server;

/// Default Control Plane URL (official hosted instance).
pub const DEFAULT_CP_URL: &str = "https://agent-mesh.fly.dev";
