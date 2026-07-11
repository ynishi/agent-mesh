//! `revocations` table: key revocation records, keyed by (revoked) agent id.

use agent_mesh_core::identity::{AgentId, UserId};
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    pub fn create_revocation(&self, rev: &RevocationRow) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT OR REPLACE INTO revocations (agent_id, reason, revoked_by, signature, timestamp, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rev.agent_id.as_str(),
                rev.reason,
                rev.revoked_by.0.to_string(),
                rev.signature,
                rev.timestamp,
                rev.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_revocations(&self) -> Result<Vec<RevocationRow>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT agent_id, reason, revoked_by, signature, timestamp, created_at
             FROM revocations ORDER BY created_at DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut revs = Vec::new();
        while let Some(row) = rows.next()? {
            revs.push(row_to_revocation(row)?);
        }
        Ok(revs)
    }

    /// Returns `true` if the given agent_id has a revocation record.
    pub fn is_revoked(&self, agent_id: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM revocations WHERE agent_id = ?1",
            params![agent_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

/// DB row representation for a key revocation.
/// Distinct from `agent_mesh_core::message::KeyRevocation`.
pub struct RevocationRow {
    /// PRIMARY KEY.
    pub agent_id: AgentId,
    pub reason: Option<String>,
    pub revoked_by: UserId,
    /// Base64url Ed25519 signature.
    pub signature: String,
    /// Unix millis.
    pub timestamp: i64,
    /// RFC 3339 timestamp string.
    pub created_at: String,
}

fn row_to_revocation(row: &rusqlite::Row) -> Result<RevocationRow> {
    let agent_id: String = row.get(0)?;
    let reason: Option<String> = row.get(1)?;
    let revoked_by_str: String = row.get(2)?;
    let signature: String = row.get(3)?;
    let timestamp: i64 = row.get(4)?;
    let created_at: String = row.get(5)?;
    Ok(RevocationRow {
        agent_id: AgentId::from_raw(agent_id),
        reason,
        revoked_by: UserId::parse_str(&revoked_by_str)?,
        signature,
        timestamp,
        created_at,
    })
}
