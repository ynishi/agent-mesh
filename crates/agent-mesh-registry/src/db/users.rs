//! `users` table: account creation and lookup by internal id or external
//! (OIDC provider) id.

use agent_mesh_core::identity::UserId;
use agent_mesh_core::user::User;
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    /// Insert a new user row.
    pub fn create_user(&self, user: &User) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO users (id, external_id, provider, display_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                user.id.0.to_string(),
                user.external_id,
                user.provider,
                user.display_name,
                user.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a user by internal ID.
    pub fn get_user_by_id(&self, id: &UserId) -> Result<Option<User>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, external_id, provider, display_name, created_at
             FROM users WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id.0.to_string()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_user(row)?)),
            None => Ok(None),
        }
    }

    /// Fetch a user by their OIDC provider's external ID.
    pub fn get_user_by_external_id(&self, external_id: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, external_id, provider, display_name, created_at
             FROM users WHERE external_id = ?1",
        )?;
        let mut rows = stmt.query(params![external_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_user(row)?)),
            None => Ok(None),
        }
    }
}

fn row_to_user(row: &rusqlite::Row) -> Result<User> {
    let id_str: String = row.get(0)?;
    let external_id: String = row.get(1)?;
    let provider: String = row.get(2)?;
    let display_name: Option<String> = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    Ok(User {
        id: UserId::parse_str(&id_str)?,
        external_id,
        provider,
        display_name,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)?.to_utc(),
    })
}
