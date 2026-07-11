//! Sync snapshot assembly: builds a [`SyncMessage`] for a group from the
//! `agent_cards`, `acl_rules`, and `revocations` tables.

use agent_mesh_core::acl::AclRule;
use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery};
use agent_mesh_core::identity::GroupId;
use agent_mesh_core::message::KeyRevocation;
use agent_mesh_core::sync::SyncMessage;
use anyhow::Result;

use super::Database;

impl Database {
    /// Build a `SyncMessage` containing the full state snapshot for the given group.
    ///
    /// Collects peers (agent_cards), ACL rules, and all revoked keys, then assembles
    /// them into a `SyncMessage`. `relay_endpoints` and `seq` are v0.3+ concerns;
    /// they are left empty/zero here.
    pub fn build_sync_message_for_group(&self, group_id: &GroupId) -> Result<SyncMessage> {
        // 1. peers: agent_cards scoped to this group
        let query = AgentCardQuery {
            group_ids: Some(vec![*group_id]),
            ..Default::default()
        };
        let peers: Vec<AgentCard> = self.search(&query)?;

        // 2. acl_rules: AclRuleRow → AclRule
        let rule_rows = self.list_acl_rules_for_group(group_id)?;
        let acl_rules: Result<Vec<AclRule>> = rule_rows
            .into_iter()
            .map(|row| {
                let caps: Vec<String> = serde_json::from_str(&row.allowed_capabilities)?;
                Ok(AclRule {
                    source: row.source,
                    target: row.target,
                    allowed_capabilities: caps,
                })
            })
            .collect();
        let acl_rules = acl_rules?;

        // 3. revoked_keys: all revocations (global scope)
        let rev_rows = self.list_revocations()?;
        let revoked_keys: Vec<KeyRevocation> = rev_rows
            .into_iter()
            .map(|row| KeyRevocation {
                agent_id: row.agent_id,
                reason: row.reason,
                timestamp: row.timestamp,
                signature: row.signature,
            })
            .collect();

        Ok(SyncMessage {
            peers,
            acl_rules,
            revoked_keys,
            relay_endpoints: vec![],
            seq: 0,
        })
    }
}
