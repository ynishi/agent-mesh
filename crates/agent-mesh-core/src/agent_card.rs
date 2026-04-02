use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{AgentCardId, AgentId, GroupId, UserId};

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
    pub id: AgentCardId,
    /// Owner agent's identity.
    pub agent_id: AgentId,
    /// User who owns this agent.
    pub owner_id: UserId,
    /// Group this agent belongs to.
    pub group_id: GroupId,
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
    /// Whether the agent is currently connected to the relay.
    /// Populated at query time; not stored in the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentCardId, AgentId, GroupId, UserId};

    fn fixed_user_id() -> UserId {
        UserId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    fn fixed_group_id() -> GroupId {
        GroupId::parse_str("00000000-0000-0000-0000-000000000002").unwrap()
    }

    fn fixed_time() -> DateTime<Utc> {
        "2024-01-01T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn agent_card_with_owner_group_serialization() {
        let card = AgentCard {
            id: AgentCardId::new_v4(),
            agent_id: AgentId::from_raw("test-agent-id".to_string()),
            owner_id: fixed_user_id(),
            group_id: fixed_group_id(),
            name: "Test Agent".to_string(),
            description: None,
            capabilities: vec![],
            registered_at: fixed_time(),
            updated_at: fixed_time(),
            metadata: None,
            online: None,
        };

        let json = serde_json::to_string(&card).unwrap();

        // Confirm owner_id and group_id are present in the serialized form.
        assert!(
            json.contains("owner_id"),
            "owner_id must be serialized: {json}"
        );
        assert!(
            json.contains("group_id"),
            "group_id must be serialized: {json}"
        );

        let decoded: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.owner_id, card.owner_id);
        assert_eq!(decoded.group_id, card.group_id);
        assert_eq!(decoded.name, card.name);
    }
}
