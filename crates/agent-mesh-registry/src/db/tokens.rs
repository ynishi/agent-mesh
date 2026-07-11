//! `api_tokens` table: creation and hash-based verification of long-lived
//! API tokens.

use agent_mesh_core::identity::UserId;
use agent_mesh_core::user::ApiToken;
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    pub fn create_api_token(&self, token: &ApiToken) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let expires_at = token.expires_at.map(|t| t.to_rfc3339());
        conn.execute(
            "INSERT INTO api_tokens (token_hash, user_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                token.token_hash,
                token.user_id.0.to_string(),
                token.created_at.to_rfc3339(),
                expires_at,
            ],
        )?;
        Ok(())
    }

    /// Verify an API token by its pre-hashed value.
    /// Returns `Some(UserId)` if the token exists and has not expired, `None` otherwise.
    /// The caller (auth.rs, Phase 1-3) is responsible for hashing the raw token before calling this method.
    pub fn verify_api_token(&self, token_hash: &str) -> Result<Option<UserId>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt =
            conn.prepare("SELECT user_id, expires_at FROM api_tokens WHERE token_hash = ?1")?;
        let mut rows = stmt.query(params![token_hash])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let user_id_str: String = row.get(0)?;
                let expires_at_str: Option<String> = row.get(1)?;

                // Check expiry: if expires_at is set and in the past, treat as expired.
                if let Some(exp_str) = expires_at_str {
                    let exp = chrono::DateTime::parse_from_rfc3339(&exp_str)?.to_utc();
                    if exp < chrono::Utc::now() {
                        return Ok(None);
                    }
                }

                Ok(Some(UserId::parse_str(&user_id_str)?))
            }
        }
    }
}
