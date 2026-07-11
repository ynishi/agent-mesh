//! Shared protocol types and cryptography for the agent-mesh network.
//!
//! # Architecture
//!
//! `agent-mesh-core` is the dependency root of the workspace: every other
//! crate (`agent-mesh-sdk`, `agent-mesh-relay`, `agent-mesh-registry`,
//! `agent-meshd`, `agent-meshctl`) depends on it, and it depends on none of
//! them. It has no network or storage IO of its own — it defines the wire
//! format and the trust primitives that the rest of the mesh is built on.
//!
//! - [`identity`] — Ed25519 [`identity::AgentKeypair`] / [`identity::AgentId`],
//!   the base identity all authentication and signing derives from.
//! - [`noise`] — Noise_XX (X25519 + ChaChaPoly) session transport for
//!   end-to-end encrypted agent-to-agent messages that pass through an
//!   untrusted relay.
//! - [`message`] — [`message::MeshEnvelope`] wire format routed by the relay
//!   and (optionally) encrypted by [`noise`].
//! - [`agent_card`] — capability advertisement (`AgentCard`) used by the
//!   registry for discovery.
//! - [`acl`] — [`acl::AclRule`] / [`acl::AclPolicy`], the authorization model
//!   enforced by meshd before forwarding a request to the local agent.
//! - [`user`] — user/group/token model (`ApiToken`, `SetupKey`) for the
//!   control-plane (registry) API; see [`user`] module docs for the full key
//!   separation table.
//! - [`sync`] — [`sync::SyncMessage`], the state snapshot the registry
//!   (control plane) pushes to connected meshd instances.
//! - [`error`] — shared [`error::ProtoError`] type used across the above.
#![warn(missing_docs)]

pub mod acl;
pub mod agent_card;
pub mod error;
pub mod identity;
pub mod message;
pub mod noise;
pub mod sync;
pub mod user;
