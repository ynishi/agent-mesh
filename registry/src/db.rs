use anyhow::Result;
use mesh_proto::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use mesh_proto::identity::AgentId;
use rusqlite::{params, Connection};
use std::sync::Mutex;
use uuid::Uuid;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_cards (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                capabilities TEXT NOT NULL,
                metadata TEXT,
                registered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_agent_id ON agent_cards(agent_id);
            CREATE INDEX IF NOT EXISTS idx_name ON agent_cards(name);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn register(&self, reg: &AgentCardRegistration) -> Result<AgentCard> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let now = chrono::Utc::now();
        let id = Uuid::new_v4();
        let caps_json = serde_json::to_string(&reg.capabilities)?;
        let meta_json = reg
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        conn.execute(
            "INSERT INTO agent_cards (id, agent_id, name, description, capabilities, metadata, registered_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.to_string(),
                reg.agent_id.as_str(),
                reg.name,
                reg.description,
                caps_json,
                meta_json,
                now.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;

        Ok(AgentCard {
            id,
            agent_id: reg.agent_id.clone(),
            name: reg.name.clone(),
            description: reg.description.clone(),
            capabilities: reg.capabilities.clone(),
            registered_at: now,
            updated_at: now,
            metadata: reg.metadata.clone(),
            online: None,
        })
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<AgentCard>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, name, description, capabilities, metadata, registered_at, updated_at
             FROM agent_cards WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_card(row)?)),
            None => Ok(None),
        }
    }

    pub fn search(&self, query: &AgentCardQuery) -> Result<Vec<AgentCard>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let mut sql = String::from(
            "SELECT id, agent_id, name, description, capabilities, metadata, registered_at, updated_at
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

    pub fn update(&self, id: &Uuid, reg: &AgentCardRegistration) -> Result<Option<AgentCard>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        // Verify the card exists and agent_id matches.
        let existing = {
            let mut stmt = conn.prepare("SELECT agent_id FROM agent_cards WHERE id = ?1")?;
            let mut rows = stmt.query(params![id.to_string()])?;
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
                id.to_string(),
            ],
        )?;

        drop(conn);
        self.get_by_id(id)
    }

    pub fn delete(&self, id: &Uuid) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let affected = conn.execute(
            "DELETE FROM agent_cards WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(affected > 0)
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

    Ok(AgentCard {
        id: Uuid::parse_str(&id_str)?,
        agent_id: AgentId::from_raw(agent_id_str),
        name,
        description,
        capabilities: serde_json::from_str(&caps_json)?,
        metadata: meta_json.map(|s| serde_json::from_str(&s)).transpose()?,
        registered_at: chrono::DateTime::parse_from_rfc3339(&registered_str)?.to_utc(),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_str)?.to_utc(),
        online: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_proto::agent_card::{AgentCardQuery, AgentCardRegistration, Capability};
    use mesh_proto::identity::AgentId;

    fn test_db() -> Database {
        Database::open(":memory:").expect("in-memory db")
    }

    fn make_reg(agent_id: &str, name: &str, caps: Vec<&str>) -> AgentCardRegistration {
        AgentCardRegistration {
            agent_id: AgentId::from_raw(agent_id.to_string()),
            name: name.to_string(),
            description: Some(format!("{name} description")),
            capabilities: caps
                .into_iter()
                .map(|c| Capability {
                    name: c.to_string(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                })
                .collect(),
            metadata: None,
        }
    }

    #[test]
    fn register_and_get_by_id() {
        let db = test_db();
        let reg = make_reg("agent-1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg).unwrap();

        assert_eq!(card.name, "Alice");
        assert_eq!(card.agent_id.as_str(), "agent-1");
        assert_eq!(card.capabilities.len(), 1);
        assert_eq!(card.capabilities[0].name, "scheduling");

        let fetched = db.get_by_id(&card.id).unwrap().unwrap();
        assert_eq!(fetched.id, card.id);
        assert_eq!(fetched.name, "Alice");
    }

    #[test]
    fn get_by_id_not_found() {
        let db = test_db();
        let result = db.get_by_id(&Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn search_by_capability() {
        let db = test_db();
        db.register(&make_reg("a1", "Alice", vec!["scheduling", "contact"]))
            .unwrap();
        db.register(&make_reg("a2", "Bob", vec!["contact"]))
            .unwrap();
        db.register(&make_reg("a3", "Carol", vec!["billing"]))
            .unwrap();

        let results = db
            .search(&AgentCardQuery {
                capability: Some("contact".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Alice"));
        assert!(names.contains(&"Bob"));
    }

    #[test]
    fn search_by_name() {
        let db = test_db();
        db.register(&make_reg("a1", "Alice", vec!["scheduling"]))
            .unwrap();
        db.register(&make_reg("a2", "Bob", vec!["scheduling"]))
            .unwrap();

        let results = db
            .search(&AgentCardQuery {
                search: Some("Alice".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[test]
    fn search_by_agent_id() {
        let db = test_db();
        db.register(&make_reg("a1", "Alice", vec!["scheduling"]))
            .unwrap();
        db.register(&make_reg("a2", "Bob", vec!["scheduling"]))
            .unwrap();

        let results = db
            .search(&AgentCardQuery {
                agent_id: Some(AgentId::from_raw("a1".to_string())),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[test]
    fn search_empty_result() {
        let db = test_db();
        db.register(&make_reg("a1", "Alice", vec!["scheduling"]))
            .unwrap();

        let results = db
            .search(&AgentCardQuery {
                capability: Some("nonexistent".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn update_card() {
        let db = test_db();
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg).unwrap();

        let updated_reg = make_reg("a1", "Alice v2", vec!["scheduling", "contact"]);
        let updated = db.update(&card.id, &updated_reg).unwrap().unwrap();
        assert_eq!(updated.name, "Alice v2");
        assert_eq!(updated.capabilities.len(), 2);
    }

    #[test]
    fn update_agent_id_mismatch() {
        let db = test_db();
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg).unwrap();

        let wrong_reg = make_reg("a2", "Alice", vec!["scheduling"]);
        let result = db.update(&card.id, &wrong_reg);
        assert!(result.is_err());
    }

    #[test]
    fn update_not_found() {
        let db = test_db();
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let result = db.update(&Uuid::new_v4(), &reg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_card() {
        let db = test_db();
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg).unwrap();

        assert!(db.delete(&card.id).unwrap());
        assert!(db.get_by_id(&card.id).unwrap().is_none());
    }

    #[test]
    fn delete_not_found() {
        let db = test_db();
        assert!(!db.delete(&Uuid::new_v4()).unwrap());
    }

    #[test]
    fn register_with_metadata() {
        let db = test_db();
        let mut reg = make_reg("a1", "Alice", vec!["scheduling"]);
        reg.metadata = Some(serde_json::json!({"version": "1.0", "rate_limit": 100}));
        let card = db.register(&reg).unwrap();

        let fetched = db.get_by_id(&card.id).unwrap().unwrap();
        let meta = fetched.metadata.unwrap();
        assert_eq!(meta["version"], "1.0");
        assert_eq!(meta["rate_limit"], 100);
    }
}
