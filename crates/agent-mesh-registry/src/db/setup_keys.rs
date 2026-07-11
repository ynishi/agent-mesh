//! `setup_keys` table: one-off and reusable enrollment keys, with atomic
//! expiry/uses-remaining verification.

use agent_mesh_core::identity::{GroupId, UserId};
use agent_mesh_core::user::{SetupKey, SetupKeyUsage};
use anyhow::Result;
use rusqlite::params;
use uuid::Uuid;

use super::Database;

impl Database {
    pub fn create_setup_key(&self, key: &SetupKey) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let usage_str = usage_to_db_str(&key.usage);
        conn.execute(
            "INSERT INTO setup_keys (id, key_hash, user_id, group_id, usage, uses_remaining, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key.id.to_string(),
                key.key_hash,
                key.user_id.0.to_string(),
                key.group_id.0.to_string(),
                usage_str,
                key.uses_remaining.map(|n| n as i64),
                key.created_at.to_rfc3339(),
                key.expires_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Verify a setup key by its pre-hashed value.
    ///
    /// Checks expiry and remaining uses atomically. On success:
    /// - OneOff key: sets `uses_remaining = 0` (marks as consumed; physical row kept for audit)
    /// - Reusable key: decrements `uses_remaining` by 1
    ///
    /// Returns `Some(SetupKey)` if valid and available, `None` otherwise.
    pub fn verify_setup_key(&self, key_hash: &str) -> Result<Option<SetupKey>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let tx = conn.unchecked_transaction()?;

        type SetupKeyRow = (
            String,
            String,
            String,
            String,
            String,
            Option<i64>,
            String,
            String,
        );
        let result: Option<SetupKeyRow> = {
            let mut stmt = tx.prepare(
                "SELECT id, key_hash, user_id, group_id, usage, uses_remaining, created_at, expires_at
                 FROM setup_keys WHERE key_hash = ?1",
            )?;
            let mut rows = stmt.query(params![key_hash])?;
            match rows.next()? {
                None => None,
                Some(row) => Some((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                )),
            }
        };

        let (id_str, kh, uid_str, gid_str, usage_str, uses_remaining_raw, created_str, expires_str) =
            match result {
                None => {
                    tx.rollback()?;
                    return Ok(None);
                }
                Some(r) => r,
            };

        // Expiry check
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_str)?.to_utc();
        if expires_at < chrono::Utc::now() {
            tx.rollback()?;
            return Ok(None);
        }

        // Usage check and decrement
        let usage = db_str_to_usage(&usage_str, uses_remaining_raw)?;
        match &usage {
            SetupKeyUsage::OneOff => {
                // uses_remaining == None means unused; 0 means already used
                if uses_remaining_raw == Some(0) {
                    tx.rollback()?;
                    return Ok(None);
                }
                // Mark as consumed: set uses_remaining = 0
                tx.execute(
                    "UPDATE setup_keys SET uses_remaining = 0 WHERE key_hash = ?1",
                    params![key_hash],
                )?;
            }
            SetupKeyUsage::Reusable { .. } => match uses_remaining_raw {
                None | Some(0) => {
                    tx.rollback()?;
                    return Ok(None);
                }
                Some(n) => {
                    tx.execute(
                        "UPDATE setup_keys SET uses_remaining = ?1 WHERE key_hash = ?2",
                        params![n - 1, key_hash],
                    )?;
                }
            },
        }

        tx.commit()?;

        let id = Uuid::parse_str(&id_str)?;
        let user_id = UserId::parse_str(&uid_str)?;
        let group_id = GroupId::parse_str(&gid_str)?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)?.to_utc();

        // Reflect the updated uses_remaining in the returned key
        let new_uses_remaining = match &usage {
            SetupKeyUsage::OneOff => None,
            SetupKeyUsage::Reusable { .. } => uses_remaining_raw.map(|n| (n - 1) as u32),
        };

        Ok(Some(SetupKey {
            id,
            key_hash: kh,
            user_id,
            group_id,
            usage,
            uses_remaining: new_uses_remaining,
            created_at,
            expires_at,
        }))
    }

    pub fn list_setup_keys(&self, user_id: &UserId) -> Result<Vec<SetupKey>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, key_hash, user_id, group_id, usage, uses_remaining, created_at, expires_at
             FROM setup_keys WHERE user_id = ?1
             ORDER BY created_at DESC",
        )?;
        let mut rows = stmt.query(params![user_id.0.to_string()])?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next()? {
            keys.push(row_to_setup_key(row)?);
        }
        Ok(keys)
    }

    /// Revoke (physically delete) a setup key by id, only if owned by the given user.
    ///
    /// Returns `true` if deleted, `false` if not found or not owned by user.
    pub fn revoke_setup_key(&self, id: &Uuid, user_id: &UserId) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let affected = conn.execute(
            "DELETE FROM setup_keys WHERE id = ?1 AND user_id = ?2",
            params![id.to_string(), user_id.0.to_string()],
        )?;
        Ok(affected > 0)
    }
}

/// Serialize `SetupKeyUsage` to a DB string.
///
/// - `OneOff` → `"one_off"`
/// - `Reusable { max_uses }` → `{"reusable": N}` (JSON)
fn usage_to_db_str(usage: &SetupKeyUsage) -> String {
    match usage {
        SetupKeyUsage::OneOff => "one_off".to_string(),
        SetupKeyUsage::Reusable { max_uses } => {
            format!(r#"{{"reusable":{}}}"#, max_uses)
        }
    }
}

/// Deserialize a DB string back into `SetupKeyUsage`.
///
/// `uses_remaining_raw` is the raw DB value; for Reusable keys, `max_uses`
/// is recovered from the `usage` JSON because the DDL has no separate column.
fn db_str_to_usage(usage_str: &str, uses_remaining_raw: Option<i64>) -> Result<SetupKeyUsage> {
    if usage_str == "one_off" {
        return Ok(SetupKeyUsage::OneOff);
    }
    // Try parsing as {"reusable": N}
    let v: serde_json::Value = serde_json::from_str(usage_str)
        .map_err(|e| anyhow::anyhow!("unknown usage format '{usage_str}': {e}"))?;
    if let Some(max_uses) = v.get("reusable").and_then(|n| n.as_u64()) {
        return Ok(SetupKeyUsage::Reusable {
            max_uses: max_uses as u32,
        });
    }
    // Fallback: if uses_remaining is available, use it as max_uses
    if let Some(n) = uses_remaining_raw {
        return Ok(SetupKeyUsage::Reusable { max_uses: n as u32 });
    }
    Err(anyhow::anyhow!("unknown usage format: {usage_str}"))
}

fn row_to_setup_key(row: &rusqlite::Row) -> Result<SetupKey> {
    let id_str: String = row.get(0)?;
    let key_hash: String = row.get(1)?;
    let user_id_str: String = row.get(2)?;
    let group_id_str: String = row.get(3)?;
    let usage_str: String = row.get(4)?;
    let uses_remaining_raw: Option<i64> = row.get(5)?;
    let created_at_str: String = row.get(6)?;
    let expires_at_str: String = row.get(7)?;

    let usage = db_str_to_usage(&usage_str, uses_remaining_raw)?;
    let uses_remaining = match &usage {
        SetupKeyUsage::OneOff => None,
        SetupKeyUsage::Reusable { .. } => uses_remaining_raw.map(|n| n as u32),
    };

    Ok(SetupKey {
        id: Uuid::parse_str(&id_str)?,
        key_hash,
        user_id: UserId::parse_str(&user_id_str)?,
        group_id: GroupId::parse_str(&group_id_str)?,
        usage,
        uses_remaining,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)?.to_utc(),
        expires_at: chrono::DateTime::parse_from_rfc3339(&expires_at_str)?.to_utc(),
    })
}
