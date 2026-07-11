//! `acl_rules` table: capability-grant rules between agents, scoped to a
//! group.

use agent_mesh_core::identity::{AgentId, GroupId, UserId};
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    /// Insert a new ACL rule row.
    pub fn create_acl_rule(&self, rule: &AclRuleRow) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO acl_rules (id, group_id, source, target, allowed_capabilities, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rule.id,
                rule.group_id.0.to_string(),
                rule.source.as_str(),
                rule.target.as_str(),
                rule.allowed_capabilities,
                rule.created_by.0.to_string(),
                rule.created_at,
            ],
        )?;
        Ok(())
    }

    /// List all ACL rules for a group, oldest first.
    pub fn list_acl_rules_for_group(&self, group_id: &GroupId) -> Result<Vec<AclRuleRow>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, group_id, source, target, allowed_capabilities, created_by, created_at
             FROM acl_rules WHERE group_id = ?1
             ORDER BY created_at ASC",
        )?;
        let mut rows = stmt.query(params![group_id.0.to_string()])?;
        let mut rules = Vec::new();
        while let Some(row) = rows.next()? {
            rules.push(row_to_acl_rule(row)?);
        }
        Ok(rules)
    }

    /// Delete an ACL rule by id, only if it belongs to the given group.
    ///
    /// Returns `true` if deleted, `false` if not found or not in the group.
    pub fn delete_acl_rule(&self, id: &str, group_id: &GroupId) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let affected = conn.execute(
            "DELETE FROM acl_rules WHERE id = ?1 AND group_id = ?2",
            params![id, group_id.0.to_string()],
        )?;
        Ok(affected > 0)
    }
}

/// DB row representation for an ACL rule.
/// Distinct from `agent_mesh_core::acl::AclRule` — this is the persistence layer struct.
pub struct AclRuleRow {
    /// Rule ID (UUID string).
    pub id: String,
    /// Group the rule is scoped to.
    pub group_id: GroupId,
    /// Agent the rule grants outbound access *from*.
    pub source: AgentId,
    /// Agent the rule grants access *to*.
    pub target: AgentId,
    /// JSON array of capability names.
    pub allowed_capabilities: String,
    /// User who created the rule.
    pub created_by: UserId,
    /// RFC 3339 timestamp string.
    pub created_at: String,
}

fn row_to_acl_rule(row: &rusqlite::Row) -> Result<AclRuleRow> {
    let id: String = row.get(0)?;
    let group_id_str: String = row.get(1)?;
    let source: String = row.get(2)?;
    let target: String = row.get(3)?;
    let allowed_capabilities: String = row.get(4)?;
    let created_by_str: String = row.get(5)?;
    let created_at: String = row.get(6)?;
    Ok(AclRuleRow {
        id,
        group_id: GroupId::parse_str(&group_id_str)?,
        source: AgentId::from_raw(source),
        target: AgentId::from_raw(target),
        allowed_capabilities,
        created_by: UserId::parse_str(&created_by_str)?,
        created_at,
    })
}
