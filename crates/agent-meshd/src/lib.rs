//! Local daemon (sidecar) that connects a locally-running agent to the
//! agent-mesh network.
//!
//! # Architecture
//!
//! `agent-meshd` runs alongside a user's agent process and is the only part
//! of the mesh that agent typically talks to directly (over plain local
//! HTTP); meshd handles all relay connectivity, encryption, and
//! authorization on its behalf.
//!
//! - [`node`] — [`node::MeshNode`], the daemon's state machine
//!   (`Started` → `Authenticated` → `Syncing` → `Connected`) and per-peer
//!   Noise session state, built on `agent-mesh-core`'s identity and noise
//!   transport.
//! - [`cp_sync`] — reconnecting WebSocket client that subscribes to the
//!   control plane (`agent-mesh-registry`)'s sync endpoint and applies each
//!   `agent_mesh_core::sync::SyncMessage` to local state (peers, ACL).
//! - [`proxy`] — forwards a decrypted incoming request to the local agent's
//!   HTTP endpoint ([`config::NodeConfig::local_agent_url`]) and returns its
//!   response back through the Noise session.
//! - [`local_api`] — local-only HTTP API the daemon exposes for the CLI
//!   (`agent-meshctl`) to drive requests/registration through the daemon
//!   without re-implementing relay/session handling.
//! - [`config`] — [`config::NodeConfig`], on-disk daemon configuration
//!   including the Ed25519 secret key and ACL policy, with hot reload.
//!
//! meshd depends on `agent-mesh-core` for identity/crypto/ACL types, on a
//! relay (`agent-mesh-relay`) over WebSocket for message transport, and on
//! a registry (`agent-mesh-registry`) over HTTP/WebSocket for
//! authentication and state sync.
pub mod config;
pub mod cp_sync;
pub mod local_api;
pub mod node;
pub mod proxy;
