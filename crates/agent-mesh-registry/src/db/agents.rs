//! `agent_cards` table: registration, lookup, search, update, and delete for
//! [`AgentCard`] records.

use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
    pub fn register(
        &self,
        reg: &AgentCardRegistration,
        owner_id: UserId,
        group_id: GroupId,
    ) -> Result<AgentCard> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let now = chrono::Utc::now();
        let id = AgentCardId::new_v4();
        let caps_json = serde_json::to_string(&reg.capabilities)?;
        let meta_json = reg
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        conn.execute(
            "INSERT INTO agent_cards
             (id, agent_id, name, description, capabilities, metadata, registered_at, updated_at, owner_id, group_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id.0.to_string(),
                reg.agent_id.as_str(),
                reg.name,
                reg.description,
                caps_json,
                meta_json,
                now.to_rfc3339(),
                now.to_rfc3339(),
                owner_id.0.to_string(),
                group_id.0.to_string(),
            ],
        )?;

        Ok(AgentCard {
            id,
            agent_id: reg.agent_id.clone(),
            owner_id,
            group_id,
            name: reg.name.clone(),
            description: reg.description.clone(),
            capabilities: reg.capabilities.clone(),
            registered_at: now,
            updated_at: now,
            metadata: reg.metadata.clone(),
            online: None,
        })
    }

    pub fn get_by_id(&self, id: &AgentCardId) -> Result<Option<AgentCard>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, name, description, capabilities, metadata, registered_at, updated_at, owner_id, group_id
             FROM agent_cards WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id.0.to_string()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_card(row)?)),
            None => Ok(None),
        }
    }

    pub fn search(&self, query: &AgentCardQuery) -> Result<Vec<AgentCard>> {
        // If group_ids is explicitly set to an empty list, no groups match — return early.
        if let Some(ref group_ids) = query.group_ids {
            if group_ids.is_empty() {
                return Ok(vec![]);
            }
        }

        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let mut sql = String::from(
            "SELECT id, agent_id, name, description, capabilities, metadata, registered_at, updated_at, owner_id, group_id
             FROM agent_cards WHERE 1=1",
        );
        let mut param_values: Vec<String> = Vec::new();

        if let Some(ref agent_id) = query.agent_id {
            param_values.push(agent_id.as_str().to_string());
            sql.push_str(&format!(" AND agent_id = ?{}", param_values.len()));
        }
        if let Some(ref search) = query.search {
            let like = format!("%{search}%");
            param_values.push(like);
            let idx = param_values.len();
            sql.push_str(&format!(
                " AND (name LIKE ?{idx} OR description LIKE ?{idx})"
            ));
        }
        if let Some(ref group_ids) = query.group_ids {
            // group_ids is guaranteed non-empty here (early return above handles empty case).
            let placeholders: Vec<String> = group_ids
                .iter()
                .map(|gid| {
                    param_values.push(gid.0.to_string());
                    format!("?{}", param_values.len())
                })
                .collect();
            sql.push_str(&format!(" AND group_id IN ({})", placeholders.join(",")));
        }

        sql.push_str(" ORDER BY updated_at DESC LIMIT 100");

        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = param_values
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        let mut rows = stmt.query(params.as_slice())?;

        let mut cards = Vec::new();
        while let Some(row) = rows.next()? {
            let card = row_to_card(row)?;
            // Post-filter by capability if specified.
            if let Some(ref cap_name) = query.capability {
                if card.capabilities.iter().any(|c| c.name == *cap_name) {
                    cards.push(card);
                }
            } else {
                cards.push(card);
            }
        }
        Ok(cards)
    }

    pub fn update(
        &self,
        id: &AgentCardId,
        reg: &AgentCardRegistration,
    ) -> Result<Option<AgentCard>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        // Verify the card exists and agent_id matches.
        let existing = {
            let mut stmt = conn.prepare("SELECT agent_id FROM agent_cards WHERE id = ?1")?;
            let mut rows = stmt.query(params![id.0.to_string()])?;
            match rows.next()? {
                Some(row) => {
                    let existing_agent_id: String = row.get(0)?;
                    existing_agent_id
                }
                None => return Ok(None),
            }
        };

        if existing != reg.agent_id.as_str() {
            return Err(anyhow::anyhow!(
                "agent_id mismatch: card belongs to {}, update from {}",
                existing,
                reg.agent_id
            ));
        }

        let now = chrono::Utc::now();
        let caps_json = serde_json::to_string(&reg.capabilities)?;
        let meta_json = reg
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        conn.execute(
            "UPDATE agent_cards SET name = ?1, description = ?2, capabilities = ?3, metadata = ?4, updated_at = ?5
             WHERE id = ?6",
            params![
                reg.name,
                reg.description,
                caps_json,
                meta_json,
                now.to_rfc3339(),
                id.0.to_string(),
            ],
        )?;

        drop(conn);
        self.get_by_id(id)
    }

    pub fn delete(&self, id: &AgentCardId) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let affected = conn.execute(
            "DELETE FROM agent_cards WHERE id = ?1",
            params![id.0.to_string()],
        )?;
        Ok(affected > 0)
    }

    // ── AgentCard count helper ────────────────────────────────────────────────

    /// Count of agent_cards rows (used for /status endpoint).
    pub fn count_agent_cards(&self) -> Result<usize> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM agent_cards", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

fn row_to_card(row: &rusqlite::Row) -> Result<AgentCard> {
    let id_str: String = row.get(0)?;
    let agent_id_str: String = row.get(1)?;
    let name: String = row.get(2)?;
    let description: Option<String> = row.get(3)?;
    let caps_json: String = row.get(4)?;
    let meta_json: Option<String> = row.get(5)?;
    let registered_str: String = row.get(6)?;
    let updated_str: String = row.get(7)?;
    let owner_id_str: String = row.get(8)?;
    let group_id_str: String = row.get(9)?;

    Ok(AgentCard {
        id: AgentCardId::parse_str(&id_str)?,
        agent_id: AgentId::from_raw(agent_id_str),
        owner_id: UserId::parse_str(&owner_id_str)?,
        group_id: GroupId::parse_str(&group_id_str)?,
        name,
        description,
        capabilities: serde_json::from_str(&caps_json)?,
        metadata: meta_json.map(|s| serde_json::from_str(&s)).transpose()?,
        registered_at: chrono::DateTime::parse_from_rfc3339(&registered_str)?.to_utc(),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)?.to_utc(),
        online: None,
    })
}
