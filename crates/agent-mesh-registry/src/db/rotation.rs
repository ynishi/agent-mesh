//! Key rotation workflow: pending-key dual-lookup, initiating a rotation,
//! completing it atomically (rewriting ACL references and revoking the old
//! key), and listing rotations whose grace period has expired.

use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::Database;

/// Result returned by [`Database::complete_key_rotation`].
pub struct RotationResult {
    pub card_id: AgentCardId,
    pub old_agent_id: AgentId,
    pub new_agent_id: AgentId,
    pub group_id: GroupId,
    /// Number of ACL rules rewritten (source + target combined).
    pub acl_rules_updated: usize,
}

impl Database {
    /// Return the group_id for a given agent_id string, or None if not found.
    ///
    /// Dual-lookup: also matches `pending_agent_id` during the grace period so that
    /// gate verify accepts the new key before rotation completes.
    pub fn get_agent_group_id(&self, agent_id: &str) -> Result<Option<GroupId>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT group_id FROM agent_cards \
             WHERE agent_id = ?1 \
                OR (pending_agent_id = ?1 AND rotation_expires_at > datetime('now')) \
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let gid_str: String = row.get(0)?;
                Ok(Some(GroupId::parse_str(&gid_str)?))
            }
        }
    }

    /// Initiate a key rotation for the given AgentCard.
    ///
    /// Stores `new_agent_id` as `pending_agent_id` with an expiry of `expires_at`.
    /// Returns an error if a rotation is already in progress.
    pub fn start_key_rotation(
        &self,
        card_id: &AgentCardId,
        new_agent_id: &AgentId,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        // Check that no rotation is currently pending.
        let pending: Option<String> = conn
            .query_row(
                "SELECT pending_agent_id FROM agent_cards WHERE id = ?1",
                params![card_id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if pending.is_some() {
            anyhow::bail!("rotation already in progress for card {card_id}");
        }

        let updated = conn.execute(
            "UPDATE agent_cards \
             SET pending_agent_id = ?1, rotation_expires_at = ?2 \
             WHERE id = ?3",
            params![
                new_agent_id.as_str(),
                expires_at.to_rfc3339(),
                card_id.to_string(),
            ],
        )?;

        if updated == 0 {
            anyhow::bail!("agent card not found: {card_id}");
        }
        Ok(())
    }

    /// Complete an in-progress key rotation atomically.
    ///
    /// Executes in a single SQLite transaction:
    /// 1. Reads `agent_id`, `pending_agent_id`, `group_id` from `agent_cards`.
    /// 2. Rewrites all ACL rules whose `source` or `target` equals `old_agent_id`.
    /// 3. Updates `agent_cards`: sets `agent_id = new`, clears `pending_agent_id` /
    ///    `rotation_expires_at`.
    /// 4. Inserts a revocation record for the old key.
    ///
    /// Returns `Err` if no rotation is pending (`pending_agent_id IS NULL`) or
    /// if the card does not exist.
    ///
    /// # Deadlock safety
    ///
    /// The Mutex is locked **once** for the entire operation. This method must NOT
    /// call any other `&self` method that also acquires the Mutex.
    pub fn complete_key_rotation(
        &self,
        card_id: &AgentCardId,
        revoked_by: UserId,
    ) -> Result<RotationResult> {
        let mut conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        // --- 1. Read current state (must be done on the same connection) ---
        let row: Option<(String, Option<String>, String)> = conn
            .query_row(
                "SELECT agent_id, pending_agent_id, group_id FROM agent_cards WHERE id = ?1",
                params![card_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let (old_agent_id_str, pending_str, group_id_str) =
            row.ok_or_else(|| anyhow::anyhow!("agent card not found: {card_id}"))?;

        let new_agent_id_str = pending_str
            .ok_or_else(|| anyhow::anyhow!("no rotation in progress for card {card_id}"))?;

        let group_id = GroupId::parse_str(&group_id_str)?;

        // --- 2. Execute multi-step transaction ---
        let tx = conn.transaction()?;

        // Rewrite ACL source references.
        let updated_source = tx.execute(
            "UPDATE acl_rules SET source = ?1 WHERE group_id = ?2 AND source = ?3",
            params![new_agent_id_str, group_id.0.to_string(), old_agent_id_str],
        )?;

        // Rewrite ACL target references.
        let updated_target = tx.execute(
            "UPDATE acl_rules SET target = ?1 WHERE group_id = ?2 AND target = ?3",
            params![new_agent_id_str, group_id.0.to_string(), old_agent_id_str],
        )?;

        let acl_rules_updated = updated_source + updated_target;

        // Update the agent card.
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE agent_cards \
             SET agent_id = ?1, pending_agent_id = NULL, rotation_expires_at = NULL, updated_at = ?2 \
             WHERE id = ?3",
            params![new_agent_id_str, now, card_id.to_string()],
        )?;

        // Insert revocation for the old key.
        // SENTINEL: CP-initiated rotation revocations use 'cp_rotation' as the signature
        // value. This is NOT a valid Ed25519 signature. meshd must skip verify() for entries
        // with this sentinel (handled in ST3).
        let timestamp_ms = chrono::Utc::now().timestamp_millis();
        tx.execute(
            "INSERT OR REPLACE INTO revocations (agent_id, reason, revoked_by, signature, timestamp, created_at)
             VALUES (?1, 'key_rotation', ?2, 'cp_rotation', ?3, ?4)",
            params![
                old_agent_id_str,
                revoked_by.0.to_string(),
                timestamp_ms,
                now,
            ],
        )?;

        tx.commit()?;

        Ok(RotationResult {
            card_id: *card_id,
            old_agent_id: AgentId::from_raw(old_agent_id_str),
            new_agent_id: AgentId::from_raw(new_agent_id_str),
            group_id,
            acl_rules_updated,
        })
    }

    /// Return all agent cards where the grace period has expired but the rotation
    /// has not yet been completed.
    ///
    /// This is a **read-only** utility for cleanup jobs. It does NOT modify state —
    /// triggering auto-completion in a read path is an anti-pattern.
    pub fn list_expired_rotations(&self) -> Result<Vec<AgentCardId>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id FROM agent_cards \
             WHERE pending_agent_id IS NOT NULL \
               AND rotation_expires_at < datetime('now')",
        )?;
        let mut rows = stmt.query([])?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            ids.push(AgentCardId::parse_str(&id_str)?);
        }
        Ok(ids)
    }
}
