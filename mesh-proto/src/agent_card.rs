use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::AgentId;

/// A capability that an agent exposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Capability {
    /// Unique name within the agent (e.g. "scheduling", "contact", "availability").
    pub name: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the input (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// JSON Schema for the output (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
}

/// Agent Card — describes an agent and its capabilities.
/// Registered in the Registry, discovered by other agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Registry-assigned unique ID.
    pub id: Uuid,
    /// Owner agent's identity.
    pub agent_id: AgentId,
    /// Human-readable display name.
    pub name: String,
    /// Description of what this agent does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Capabilities this agent exposes.
    pub capabilities: Vec<Capability>,
    /// When this card was registered.
    pub registered_at: DateTime<Utc>,
    /// When this card was last updated.
    pub updated_at: DateTime<Utc>,
    /// Optional metadata (rate limits, cost, version, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request to register or update an agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCardRegistration {
    pub agent_id: AgentId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Query parameters for searching agent cards.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCardQuery {
    /// Filter by capability name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Full-text search on name/description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Filter by agent ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
}
