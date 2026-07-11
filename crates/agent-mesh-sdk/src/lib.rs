//! Client SDK for building and calling agents on the agent-mesh network.
//!
//! # Architecture
//!
//! `agent-mesh-sdk` wraps `agent-mesh-core`'s wire types and Noise transport
//! behind two application-facing entry points, both connecting to a relay
//! over WebSocket:
//!
//! - [`MeshAgent`] (in [`agent`]) — the receiving side. Registers a
//!   [`RequestHandler`] and serves incoming requests from other agents,
//!   decrypting each request via the per-peer Noise session before handing
//!   it to the handler.
//! - [`MeshClient`] (in [`client`]) — the calling side. Establishes (or
//!   reuses) a Noise session with a target [`agent_mesh_core::identity::AgentId`]
//!   and sends encrypted requests, returning a [`ValueStream`] response.
//!
//! [`connection`] holds the shared WebSocket connection/reconnect logic used
//! by both [`agent`] and [`client`]; [`error`] defines [`SdkError`], the SDK's
//! error surface. This crate depends only on `agent-mesh-core` for identity
//! and message types — it never talks to the registry (control plane)
//! directly, only to a relay.
mod agent;
mod client;
pub(crate) mod connection;
mod error;

pub use agent::{CancelToken, MeshAgent, RequestHandler, ValueStream};
pub use client::MeshClient;
pub use connection::StreamReceiver;
pub use error::SdkError;
