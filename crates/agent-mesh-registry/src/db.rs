use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
use agent_mesh_core::user::{ApiToken, Group, GroupMember, GroupRole, User};
use anyhow::Result;
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Performance and integrity pragmas — must be set outside any transaction.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                external_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                display_name TEXT,
                created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external ON users(external_id);

            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL REFERENCES groups(id),
                user_id TEXT NOT NULL REFERENCES users(id),
                role TEXT NOT NULL DEFAULT 'member',
                PRIMARY KEY (group_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS agent_cards (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                capabilities TEXT NOT NULL,
                metadata TEXT,
                registered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                owner_id TEXT NOT NULL REFERENCES users(id),
                group_id TEXT NOT NULL REFERENCES groups(id)
            );
            CREATE INDEX IF NOT EXISTS idx_agent_id ON agent_cards(agent_id);
            CREATE INDEX IF NOT EXISTS idx_name ON agent_cards(name);

            CREATE TABLE IF NOT EXISTS api_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
            ",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Get the user's first group, creating a default one if none exist.
    pub fn ensure_user_has_group(&self, user_id: &UserId) -> Result<GroupId> {
        let groups = self.list_groups_for_user(user_id)?;
        if let Some(first) = groups.first() {
            return Ok(first.id);
        }
        // Auto-create a default group for this user.
        let group = Group {
            id: GroupId::new_v4(),
            name: "default".to_string(),
            created_by: *user_id,
            created_at: chrono::Utc::now(),
        };
        self.create_group(&group)?;
        self.add_group_member(&GroupMember {
            group_id: group.id,
            user_id: *user_id,
            role: GroupRole::Owner,
        })?;
        Ok(group.id)
    }

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

    // ── User methods ──────────────────────────────────────────────────────────

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

    // ── ApiToken methods ──────────────────────────────────────────────────────

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

    // ── Group methods ─────────────────────────────────────────────────────────

    pub fn create_group(&self, group: &Group) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO groups (id, name, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group.id.0.to_string(),
                group.name,
                group.created_by.0.to_string(),
                group.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_groups_for_user(&self, user_id: &UserId) -> Result<Vec<Group>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT g.id, g.name, g.created_by, g.created_at
             FROM groups g
             INNER JOIN group_members gm ON g.id = gm.group_id
             WHERE gm.user_id = ?1",
        )?;
        let mut rows = stmt.query(params![user_id.0.to_string()])?;
        let mut groups = Vec::new();
        while let Some(row) = rows.next()? {
            groups.push(row_to_group(row)?);
        }
        Ok(groups)
    }

    // ── GroupMember methods ───────────────────────────────────────────────────

    pub fn add_group_member(&self, member: &GroupMember) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, role)
             VALUES (?1, ?2, ?3)",
            params![
                member.group_id.0.to_string(),
                member.user_id.0.to_string(),
                group_role_to_str(&member.role),
            ],
        )?;
        Ok(())
    }

    pub fn remove_group_member(&self, group_id: &GroupId, user_id: &UserId) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Idempotent delete — no error if the membership does not exist.
        conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
            params![group_id.0.to_string(), user_id.0.to_string()],
        )?;
        Ok(())
    }

    /// Get a specific group member's role, returning `None` if not a member.
    pub fn get_group_member(
        &self,
        group_id: &GroupId,
        user_id: &UserId,
    ) -> Result<Option<GroupMember>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT group_id, user_id, role
             FROM group_members
             WHERE group_id = ?1 AND user_id = ?2",
        )?;
        let mut rows = stmt.query(params![group_id.0.to_string(), user_id.0.to_string(),])?;
        match rows.next()? {
            Some(row) => {
                let gid_str: String = row.get(0)?;
                let uid_str: String = row.get(1)?;
                let role_str: String = row.get(2)?;
                Ok(Some(GroupMember {
                    group_id: GroupId::parse_str(&gid_str)?,
                    user_id: UserId::parse_str(&uid_str)?,
                    role: str_to_group_role(&role_str)?,
                }))
            }
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

fn row_to_group(row: &rusqlite::Row) -> Result<Group> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let created_by_str: String = row.get(2)?;
    let created_at_str: String = row.get(3)?;
    Ok(Group {
        id: GroupId::parse_str(&id_str)?,
        name,
        created_by: UserId::parse_str(&created_by_str)?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)?.to_utc(),
    })
}

fn group_role_to_str(role: &GroupRole) -> &'static str {
    match role {
        GroupRole::Owner => "owner",
        GroupRole::Admin => "admin",
        GroupRole::Member => "member",
    }
}

fn str_to_group_role(s: &str) -> Result<GroupRole> {
    match s {
        "owner" => Ok(GroupRole::Owner),
        "admin" => Ok(GroupRole::Admin),
        "member" => Ok(GroupRole::Member),
        other => Err(anyhow::anyhow!("unknown group role: {other}")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::agent_card::{AgentCardQuery, AgentCardRegistration, Capability};
    use agent_mesh_core::identity::AgentId;

    fn test_db() -> Database {
        Database::open(":memory:").expect("in-memory db")
    }

    fn ensure_test_user(db: &Database) -> (UserId, GroupId) {
        let user_id = UserId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let group_id = GroupId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let conn = db.conn.lock().expect("lock");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO users (id, external_id, provider, display_name, created_at)
             VALUES (?1, 'test', 'test', 'Test User', ?2)",
            params!["00000000-0000-0000-0000-000000000001", now],
        )
        .expect("insert test user");
        conn.execute(
            "INSERT OR IGNORE INTO groups (id, name, created_by, created_at)
             VALUES (?1, 'test-group', ?2, ?3)",
            params![
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000001",
                now
            ],
        )
        .expect("insert test group");
        (user_id, group_id)
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
        let (owner_id, group_id) = ensure_test_user(&db);
        let reg = make_reg("agent-1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg, owner_id, group_id).unwrap();

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
        let result = db.get_by_id(&AgentCardId::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn search_by_capability() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(
            &make_reg("a1", "Alice", vec!["scheduling", "contact"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(&make_reg("a2", "Bob", vec!["contact"]), owner_id, group_id)
            .unwrap();
        db.register(
            &make_reg("a3", "Carol", vec!["billing"]),
            owner_id,
            group_id,
        )
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
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(
            &make_reg("a2", "Bob", vec!["scheduling"]),
            owner_id,
            group_id,
        )
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
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(
            &make_reg("a2", "Bob", vec!["scheduling"]),
            owner_id,
            group_id,
        )
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
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
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
        let (owner_id, group_id) = ensure_test_user(&db);
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg, owner_id, group_id).unwrap();

        let updated_reg = make_reg("a1", "Alice v2", vec!["scheduling", "contact"]);
        let updated = db.update(&card.id, &updated_reg).unwrap().unwrap();
        assert_eq!(updated.name, "Alice v2");
        assert_eq!(updated.capabilities.len(), 2);
    }

    #[test]
    fn update_agent_id_mismatch() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg, owner_id, group_id).unwrap();

        let wrong_reg = make_reg("a2", "Alice", vec!["scheduling"]);
        let result = db.update(&card.id, &wrong_reg);
        assert!(result.is_err());
    }

    #[test]
    fn update_not_found() {
        let db = test_db();
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let result = db.update(&AgentCardId::new_v4(), &reg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_card() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let reg = make_reg("a1", "Alice", vec!["scheduling"]);
        let card = db.register(&reg, owner_id, group_id).unwrap();

        assert!(db.delete(&card.id).unwrap());
        assert!(db.get_by_id(&card.id).unwrap().is_none());
    }

    #[test]
    fn delete_not_found() {
        let db = test_db();
        assert!(!db.delete(&AgentCardId::new_v4()).unwrap());
    }

    #[test]
    fn register_with_metadata() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let mut reg = make_reg("a1", "Alice", vec!["scheduling"]);
        reg.metadata = Some(serde_json::json!({"version": "1.0", "rate_limit": 100}));
        let card = db.register(&reg, owner_id, group_id).unwrap();

        let fetched = db.get_by_id(&card.id).unwrap().unwrap();
        let meta = fetched.metadata.unwrap();
        assert_eq!(meta["version"], "1.0");
        assert_eq!(meta["rate_limit"], 100);
    }

    // ── Helper for parameterized test user creation ───────────────────────────

    fn make_test_user(external_id: &str) -> User {
        User {
            id: UserId::new_v4(),
            external_id: external_id.to_string(),
            provider: "test".to_string(),
            display_name: Some(format!("Test {external_id}")),
            created_at: chrono::Utc::now(),
        }
    }

    // ── User tests ────────────────────────────────────────────────────────────

    #[test]
    fn create_and_get_user_by_id() {
        let db = test_db();
        let user = make_test_user("user-abc");
        db.create_user(&user).unwrap();

        let fetched = db.get_user_by_id(&user.id).unwrap().unwrap();
        assert_eq!(fetched.id, user.id);
        assert_eq!(fetched.external_id, "user-abc");
        assert_eq!(fetched.provider, "test");
        assert_eq!(fetched.display_name, Some("Test user-abc".to_string()));
    }

    #[test]
    fn get_user_by_external_id() {
        let db = test_db();
        let user = make_test_user("ext-lookup");
        db.create_user(&user).unwrap();

        let fetched = db.get_user_by_external_id("ext-lookup").unwrap().unwrap();
        assert_eq!(fetched.id, user.id);
        assert_eq!(fetched.external_id, "ext-lookup");
    }

    #[test]
    fn get_user_by_id_not_found() {
        let db = test_db();
        let result = db.get_user_by_id(&UserId::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_user_by_external_id_not_found() {
        let db = test_db();
        let result = db.get_user_by_external_id("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn create_user_duplicate_external_id() {
        let db = test_db();
        let user1 = make_test_user("dup-ext");
        db.create_user(&user1).unwrap();

        // Same external_id but different UUID — UNIQUE constraint violation expected.
        let user2 = User {
            id: UserId::new_v4(),
            external_id: "dup-ext".to_string(),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        let result = db.create_user(&user2);
        assert!(result.is_err());
    }

    // ── ApiToken tests ────────────────────────────────────────────────────────

    #[test]
    fn create_and_verify_api_token() {
        let db = test_db();
        let user = make_test_user("token-user");
        db.create_user(&user).unwrap();

        let token = ApiToken {
            token_hash: "hash-abc123".to_string(),
            user_id: user.id,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        db.create_api_token(&token).unwrap();

        let found = db.verify_api_token("hash-abc123").unwrap().unwrap();
        assert_eq!(found, user.id);
    }

    #[test]
    fn verify_api_token_not_found() {
        let db = test_db();
        let result = db.verify_api_token("nonexistent-hash").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn verify_api_token_expired() {
        let db = test_db();
        let user = make_test_user("expired-user");
        db.create_user(&user).unwrap();

        let token = ApiToken {
            token_hash: "expired-hash".to_string(),
            user_id: user.id,
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };
        db.create_api_token(&token).unwrap();

        let result = db.verify_api_token("expired-hash").unwrap();
        assert!(result.is_none());
    }

    // ── Group tests ───────────────────────────────────────────────────────────

    #[test]
    fn create_group_and_list_for_user() {
        let db = test_db();
        let user = make_test_user("group-owner");
        db.create_user(&user).unwrap();

        let group = Group {
            id: GroupId::new_v4(),
            name: "test-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).unwrap();

        let member = GroupMember {
            group_id: group.id,
            user_id: user.id,
            role: GroupRole::Owner,
        };
        db.add_group_member(&member).unwrap();

        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group.id);
        assert_eq!(groups[0].name, "test-group");
    }

    #[test]
    fn list_groups_empty() {
        let db = test_db();
        let user = make_test_user("no-group-user");
        db.create_user(&user).unwrap();

        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert!(groups.is_empty());
    }

    // ── GroupMember tests ─────────────────────────────────────────────────────

    #[test]
    fn add_and_remove_group_member() {
        let db = test_db();
        let user = make_test_user("member-user");
        db.create_user(&user).unwrap();

        let group = Group {
            id: GroupId::new_v4(),
            name: "member-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).unwrap();

        let member = GroupMember {
            group_id: group.id,
            user_id: user.id,
            role: GroupRole::Member,
        };
        db.add_group_member(&member).unwrap();

        // Verify membership exists.
        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert_eq!(groups.len(), 1);

        // Remove and verify gone.
        db.remove_group_member(&group.id, &user.id).unwrap();
        let groups_after = db.list_groups_for_user(&user.id).unwrap();
        assert!(groups_after.is_empty());
    }

    #[test]
    fn remove_nonexistent_member() {
        let db = test_db();
        let user = make_test_user("phantom-user");
        db.create_user(&user).unwrap();

        let group = Group {
            id: GroupId::new_v4(),
            name: "phantom-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).unwrap();

        // Remove a non-member — should be no-op, no error.
        let result = db.remove_group_member(&group.id, &user.id);
        assert!(result.is_ok());
    }

    // ── ensure_user_has_group tests ───────────────────────────────────────────

    #[test]
    fn ensure_user_has_group_creates_default_when_none() {
        let db = test_db();
        let user = make_test_user("new-user");
        db.create_user(&user).unwrap();

        // No groups yet.
        assert!(db.list_groups_for_user(&user.id).unwrap().is_empty());

        let group_id = db.ensure_user_has_group(&user.id).unwrap();

        // Group was created and user is a member.
        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, group_id);
        assert_eq!(groups[0].name, "default");
    }

    #[test]
    fn ensure_user_has_group_returns_existing() {
        let db = test_db();
        let user = make_test_user("existing-group-user");
        db.create_user(&user).unwrap();

        let group = Group {
            id: GroupId::new_v4(),
            name: "my-group".to_string(),
            created_by: user.id,
            created_at: chrono::Utc::now(),
        };
        db.create_group(&group).unwrap();
        db.add_group_member(&GroupMember {
            group_id: group.id,
            user_id: user.id,
            role: GroupRole::Owner,
        })
        .unwrap();

        let returned_id = db.ensure_user_has_group(&user.id).unwrap();
        assert_eq!(returned_id, group.id);

        // Still only one group.
        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn ensure_user_has_group_is_idempotent() {
        let db = test_db();
        let user = make_test_user("idempotent-user");
        db.create_user(&user).unwrap();

        let id1 = db.ensure_user_has_group(&user.id).unwrap();
        let id2 = db.ensure_user_has_group(&user.id).unwrap();
        assert_eq!(id1, id2);

        // Only one group should exist after two calls.
        let groups = db.list_groups_for_user(&user.id).unwrap();
        assert_eq!(groups.len(), 1);
    }
}
