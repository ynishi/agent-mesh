use agent_mesh_core::acl::AclRule;
use agent_mesh_core::agent_card::{AgentCard, AgentCardQuery, AgentCardRegistration};
use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
use agent_mesh_core::message::KeyRevocation;
use agent_mesh_core::sync::SyncMessage;
use agent_mesh_core::user::{
    ApiToken, Group, GroupMember, GroupRole, SetupKey, SetupKeyUsage, User,
};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;
use uuid::Uuid;

pub struct Database {
    conn: Mutex<Connection>,
}

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

            CREATE TABLE IF NOT EXISTS setup_keys (
                id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id),
                group_id TEXT NOT NULL REFERENCES groups(id),
                usage TEXT NOT NULL DEFAULT 'one_off',
                uses_remaining INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_setup_keys_hash ON setup_keys(key_hash);

            CREATE TABLE IF NOT EXISTS acl_rules (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL REFERENCES groups(id),
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                allowed_capabilities TEXT NOT NULL,
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_acl_rules_group ON acl_rules(group_id);

            CREATE TABLE IF NOT EXISTS revocations (
                agent_id TEXT PRIMARY KEY,
                reason TEXT,
                revoked_by TEXT NOT NULL REFERENCES users(id),
                signature TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            ",
        )?;

        // Idempotent column additions for key rotation support.
        // SQLite does not support IF NOT EXISTS on ADD COLUMN, so we attempt the ALTER
        // and ignore the "duplicate column name" error on subsequent opens.
        let add_col = |sql: &str| -> Result<()> {
            match conn.execute(sql, []) {
                Ok(_) => Ok(()),
                Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
                Err(e) => Err(e.into()),
            }
        };
        add_col("ALTER TABLE agent_cards ADD COLUMN pending_agent_id TEXT")?;
        add_col("ALTER TABLE agent_cards ADD COLUMN rotation_expires_at TEXT")?;

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

    // ── SetupKey methods ──────────────────────────────────────────────────────

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

    // ── AclRule methods ───────────────────────────────────────────────────────

    pub fn create_acl_rule(&self, rule: &AclRuleRow) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO acl_rules (id, group_id, source, target, allowed_capabilities, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rule.id,
                rule.group_id.0.to_string(),
                rule.source,
                rule.target,
                rule.allowed_capabilities,
                rule.created_by.0.to_string(),
                rule.created_at,
            ],
        )?;
        Ok(())
    }

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

    // ── Revocation methods ────────────────────────────────────────────────────

    pub fn create_revocation(&self, rev: &RevocationRow) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT OR REPLACE INTO revocations (agent_id, reason, revoked_by, signature, timestamp, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rev.agent_id,
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

    // ── AgentCard count helper ────────────────────────────────────────────────

    /// Count of agent_cards rows (used for /status endpoint).
    pub fn count_agent_cards(&self) -> Result<usize> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM agent_cards", [], |row| row.get(0))?;
        Ok(count as usize)
    }

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
                    source: AgentId::from_raw(row.source),
                    target: AgentId::from_raw(row.target),
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
                agent_id: AgentId::from_raw(row.agent_id),
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

// ── AclRule DB row ────────────────────────────────────────────────────────────

/// DB row representation for an ACL rule.
/// Distinct from `agent_mesh_core::acl::AclRule` — this is the persistence layer struct.
pub struct AclRuleRow {
    pub id: String,
    pub group_id: GroupId,
    /// AgentId as string.
    pub source: String,
    /// AgentId as string.
    pub target: String,
    /// JSON array of capability names.
    pub allowed_capabilities: String,
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
        source,
        target,
        allowed_capabilities,
        created_by: UserId::parse_str(&created_by_str)?,
        created_at,
    })
}

// ── Revocation DB row ─────────────────────────────────────────────────────────

/// DB row representation for a key revocation.
/// Distinct from `agent_mesh_core::message::KeyRevocation`.
pub struct RevocationRow {
    /// AgentId as string (PRIMARY KEY).
    pub agent_id: String,
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
        agent_id,
        reason,
        revoked_by: UserId::parse_str(&revoked_by_str)?,
        signature,
        timestamp,
        created_at,
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

    // ── SetupKey tests ────────────────────────────────────────────────────────

    fn make_setup_key(
        user_id: UserId,
        group_id: GroupId,
        usage: SetupKeyUsage,
        expires_in_hours: i64,
    ) -> SetupKey {
        let now = chrono::Utc::now();
        let uses_remaining = match &usage {
            SetupKeyUsage::OneOff => None,
            SetupKeyUsage::Reusable { max_uses } => Some(*max_uses),
        };
        SetupKey {
            id: Uuid::new_v4(),
            key_hash: format!("hash-{}", Uuid::new_v4()),
            user_id,
            group_id,
            usage,
            uses_remaining,
            created_at: now,
            expires_at: now + chrono::Duration::hours(expires_in_hours),
        }
    }

    #[test]
    fn create_and_verify_setup_key_oneoff() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let key = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, 24);
        db.create_setup_key(&key).unwrap();

        // First use succeeds
        let result = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(result.is_some());
        let verified = result.unwrap();
        assert_eq!(verified.id, key.id);
        assert_eq!(verified.usage, SetupKeyUsage::OneOff);

        // Second use fails (already consumed)
        let result2 = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn verify_setup_key_expired() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let key = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, -1);
        db.create_setup_key(&key).unwrap();

        let result = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn verify_setup_key_not_found() {
        let db = test_db();
        let result = db.verify_setup_key("nonexistent-hash").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn create_and_verify_setup_key_reusable() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let key = make_setup_key(
            user_id,
            group_id,
            SetupKeyUsage::Reusable { max_uses: 3 },
            24,
        );
        db.create_setup_key(&key).unwrap();

        // Use 1
        let r1 = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().uses_remaining, Some(2));

        // Use 2
        let r2 = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().uses_remaining, Some(1));

        // Use 3
        let r3 = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(r3.is_some());
        assert_eq!(r3.unwrap().uses_remaining, Some(0));

        // Use 4: exceeds max_uses
        let r4 = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(r4.is_none());
    }

    #[test]
    fn verify_setup_key_reusable_zero_uses_remaining() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        // Create a reusable key with uses_remaining already 0
        let mut key = make_setup_key(
            user_id,
            group_id,
            SetupKeyUsage::Reusable { max_uses: 0 },
            24,
        );
        key.uses_remaining = Some(0);
        db.create_setup_key(&key).unwrap();

        let result = db.verify_setup_key(&key.key_hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_setup_keys_by_user() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);

        let key1 = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, 24);
        let key2 = make_setup_key(
            user_id,
            group_id,
            SetupKeyUsage::Reusable { max_uses: 5 },
            48,
        );
        db.create_setup_key(&key1).unwrap();
        db.create_setup_key(&key2).unwrap();

        let keys = db.list_setup_keys(&user_id).unwrap();
        assert_eq!(keys.len(), 2);

        let ids: Vec<Uuid> = keys.iter().map(|k| k.id).collect();
        assert!(ids.contains(&key1.id));
        assert!(ids.contains(&key2.id));
    }

    #[test]
    fn list_setup_keys_filters_by_user() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);

        // Create a second user
        let user2 = User {
            id: UserId::new_v4(),
            external_id: "sk-test-user2".to_string(),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        db.create_user(&user2).unwrap();

        let key1 = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, 24);
        let key2 = make_setup_key(user2.id, group_id, SetupKeyUsage::OneOff, 24);
        db.create_setup_key(&key1).unwrap();
        db.create_setup_key(&key2).unwrap();

        let keys = db.list_setup_keys(&user_id).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, key1.id);
    }

    #[test]
    fn revoke_setup_key_success() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let key = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, 24);
        db.create_setup_key(&key).unwrap();

        let result = db.revoke_setup_key(&key.id, &user_id).unwrap();
        assert!(result);

        // After revoke, list should be empty
        let keys = db.list_setup_keys(&user_id).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn revoke_setup_key_wrong_owner() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);

        let user2 = User {
            id: UserId::new_v4(),
            external_id: "revoke-test-user2".to_string(),
            provider: "test".to_string(),
            display_name: None,
            created_at: chrono::Utc::now(),
        };
        db.create_user(&user2).unwrap();

        let key = make_setup_key(user_id, group_id, SetupKeyUsage::OneOff, 24);
        db.create_setup_key(&key).unwrap();

        // user2 tries to revoke user1's key
        let result = db.revoke_setup_key(&key.id, &user2.id).unwrap();
        assert!(!result);

        // Key should still exist for user1
        let keys = db.list_setup_keys(&user_id).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn revoke_setup_key_not_found() {
        let db = test_db();
        let (user_id, _) = ensure_test_user(&db);
        let result = db.revoke_setup_key(&Uuid::new_v4(), &user_id).unwrap();
        assert!(!result);
    }

    // ── search with group_ids tests ───────────────────────────────────────────

    fn ensure_test_user2(db: &Database) -> (UserId, GroupId) {
        let user_id = UserId::parse_str("00000000-0000-0000-0000-000000000011").unwrap();
        let group_id = GroupId::parse_str("00000000-0000-0000-0000-000000000012").unwrap();
        let conn = db.conn.lock().expect("lock");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO users (id, external_id, provider, display_name, created_at)
             VALUES (?1, 'test2', 'test', 'Test User2', ?2)",
            params!["00000000-0000-0000-0000-000000000011", now],
        )
        .expect("insert test user2");
        conn.execute(
            "INSERT OR IGNORE INTO groups (id, name, created_by, created_at)
             VALUES (?1, 'test-group2', ?2, ?3)",
            params![
                "00000000-0000-0000-0000-000000000012",
                "00000000-0000-0000-0000-000000000011",
                now
            ],
        )
        .expect("insert test group2");
        (user_id, group_id)
    }

    #[test]
    fn search_with_group_ids_single_group() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let (owner_id2, group_id2) = ensure_test_user2(&db);

        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(
            &make_reg("a2", "Bob", vec!["billing"]),
            owner_id2,
            group_id2,
        )
        .unwrap();

        // Search scoped to group1 only
        let results = db
            .search(&AgentCardQuery {
                group_ids: Some(vec![group_id]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[test]
    fn search_with_group_ids_multi_group() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let (owner_id2, group_id2) = ensure_test_user2(&db);

        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(
            &make_reg("a2", "Bob", vec!["billing"]),
            owner_id2,
            group_id2,
        )
        .unwrap();

        // Search scoped to both groups
        let results = db
            .search(&AgentCardQuery {
                group_ids: Some(vec![group_id, group_id2]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Alice"));
        assert!(names.contains(&"Bob"));
    }

    #[test]
    fn search_with_group_ids_empty_returns_nothing() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);

        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();

        // Empty group_ids → early return with empty vec
        let results = db
            .search(&AgentCardQuery {
                group_ids: Some(vec![]),
                ..Default::default()
            })
            .unwrap();
        assert!(
            results.is_empty(),
            "search with empty group_ids should return nothing"
        );
    }

    #[test]
    fn search_without_group_ids_returns_all() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let (owner_id2, group_id2) = ensure_test_user2(&db);

        db.register(
            &make_reg("a1", "Alice", vec!["scheduling"]),
            owner_id,
            group_id,
        )
        .unwrap();
        db.register(
            &make_reg("a2", "Bob", vec!["billing"]),
            owner_id2,
            group_id2,
        )
        .unwrap();

        // No group_ids filter → returns all
        let results = db.search(&AgentCardQuery::default()).unwrap();
        assert_eq!(results.len(), 2);
    }

    // ── AclRule DAO tests ─────────────────────────────────────────────────────

    fn make_acl_rule_row(group_id: GroupId, created_by: UserId) -> AclRuleRow {
        AclRuleRow {
            id: uuid::Uuid::new_v4().to_string(),
            group_id,
            source: "agent-src".to_string(),
            target: "agent-dst".to_string(),
            allowed_capabilities: r#"["scheduling","availability"]"#.to_string(),
            created_by,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn create_and_list_acl_rules() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let rule = make_acl_rule_row(group_id, user_id);
        db.create_acl_rule(&rule).unwrap();

        let rules = db.list_acl_rules_for_group(&group_id).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rule.id);
        assert_eq!(rules[0].source, "agent-src");
        assert_eq!(rules[0].target, "agent-dst");
        assert_eq!(rules[0].allowed_capabilities, rule.allowed_capabilities);
    }

    #[test]
    fn list_acl_rules_empty() {
        let db = test_db();
        let (_user_id, group_id) = ensure_test_user(&db);
        let rules = db.list_acl_rules_for_group(&group_id).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn list_acl_rules_scoped_to_group() {
        let db = test_db();
        let (user1, group1) = ensure_test_user(&db);
        let (user2, group2) = ensure_test_user2(&db);

        let rule1 = make_acl_rule_row(group1, user1);
        let rule2 = make_acl_rule_row(group2, user2);
        db.create_acl_rule(&rule1).unwrap();
        db.create_acl_rule(&rule2).unwrap();

        let rules_g1 = db.list_acl_rules_for_group(&group1).unwrap();
        assert_eq!(rules_g1.len(), 1);
        assert_eq!(rules_g1[0].id, rule1.id);

        let rules_g2 = db.list_acl_rules_for_group(&group2).unwrap();
        assert_eq!(rules_g2.len(), 1);
        assert_eq!(rules_g2[0].id, rule2.id);
    }

    #[test]
    fn delete_acl_rule_success() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let rule = make_acl_rule_row(group_id, user_id);
        db.create_acl_rule(&rule).unwrap();

        let deleted = db.delete_acl_rule(&rule.id, &group_id).unwrap();
        assert!(deleted);

        let rules = db.list_acl_rules_for_group(&group_id).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn delete_acl_rule_wrong_group() {
        let db = test_db();
        let (user_id, group_id) = ensure_test_user(&db);
        let (_user2, group2) = ensure_test_user2(&db);
        let rule = make_acl_rule_row(group_id, user_id);
        db.create_acl_rule(&rule).unwrap();

        // Attempt to delete from the wrong group.
        let deleted = db.delete_acl_rule(&rule.id, &group2).unwrap();
        assert!(!deleted);

        // Rule should still exist in group1.
        let rules = db.list_acl_rules_for_group(&group_id).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn delete_acl_rule_not_found() {
        let db = test_db();
        let (_user_id, group_id) = ensure_test_user(&db);
        let deleted = db.delete_acl_rule("nonexistent-id", &group_id).unwrap();
        assert!(!deleted);
    }

    // ── Revocation DAO tests ──────────────────────────────────────────────────

    fn make_revocation_row(agent_id: &str, revoked_by: UserId) -> RevocationRow {
        RevocationRow {
            agent_id: agent_id.to_string(),
            reason: Some("compromised".to_string()),
            revoked_by,
            signature: "fakesig".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn create_and_list_revocations() {
        let db = test_db();
        let (user_id, _) = ensure_test_user(&db);
        let rev = make_revocation_row("agent-revoked-1", user_id);
        db.create_revocation(&rev).unwrap();

        let revs = db.list_revocations().unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].agent_id, "agent-revoked-1");
        assert_eq!(revs[0].reason.as_deref(), Some("compromised"));
    }

    #[test]
    fn list_revocations_empty() {
        let db = test_db();
        let revs = db.list_revocations().unwrap();
        assert!(revs.is_empty());
    }

    #[test]
    fn is_revoked_true() {
        let db = test_db();
        let (user_id, _) = ensure_test_user(&db);
        let rev = make_revocation_row("agent-to-check", user_id);
        db.create_revocation(&rev).unwrap();

        assert!(db.is_revoked("agent-to-check").unwrap());
    }

    #[test]
    fn is_revoked_false() {
        let db = test_db();
        assert!(!db.is_revoked("unknown-agent").unwrap());
    }

    #[test]
    fn create_revocation_upsert() {
        // PRIMARY KEY is agent_id: second insert with same agent_id should replace.
        let db = test_db();
        let (user_id, _) = ensure_test_user(&db);
        let rev1 = make_revocation_row("dup-agent", user_id);
        db.create_revocation(&rev1).unwrap();

        let rev2 = RevocationRow {
            agent_id: "dup-agent".to_string(),
            reason: Some("second reason".to_string()),
            revoked_by: user_id,
            signature: "sig2".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        db.create_revocation(&rev2).unwrap();

        let revs = db.list_revocations().unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].reason.as_deref(), Some("second reason"));
    }

    // ── AgentCard count & group lookup tests ─────────────────────────────────

    #[test]
    fn count_agent_cards_zero() {
        let db = test_db();
        assert_eq!(db.count_agent_cards().unwrap(), 0);
    }

    #[test]
    fn count_agent_cards_after_register() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(&make_reg("a1", "Alice", vec![]), owner_id, group_id)
            .unwrap();
        db.register(&make_reg("a2", "Bob", vec![]), owner_id, group_id)
            .unwrap();
        assert_eq!(db.count_agent_cards().unwrap(), 2);
    }

    #[test]
    fn get_agent_group_id_found() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        db.register(
            &make_reg("lookup-agent", "Lookup", vec![]),
            owner_id,
            group_id,
        )
        .unwrap();

        let found = db.get_agent_group_id("lookup-agent").unwrap();
        assert_eq!(found, Some(group_id));
    }

    #[test]
    fn get_agent_group_id_not_found() {
        let db = test_db();
        let found = db.get_agent_group_id("ghost-agent").unwrap();
        assert!(found.is_none());
    }

    // ── Key rotation tests ────────────────────────────────────────────────────

    #[test]
    fn start_key_rotation_sets_pending() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let card = db
            .register(
                &make_reg("rot-agent", "RotAgent", vec![]),
                owner_id,
                group_id,
            )
            .unwrap();

        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
        db.start_key_rotation(
            &card.id,
            &AgentId::from_raw("new-agent-id".to_string()),
            expires_at,
        )
        .unwrap();

        // The new agent_id should now be found via dual-lookup.
        let found = db.get_agent_group_id("new-agent-id").unwrap();
        assert_eq!(found, Some(group_id));
    }

    #[test]
    fn start_key_rotation_duplicate_rejected() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let card = db
            .register(
                &make_reg("dup-rot-agent", "DupRot", vec![]),
                owner_id,
                group_id,
            )
            .unwrap();

        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
        db.start_key_rotation(
            &card.id,
            &AgentId::from_raw("pending-new-1".to_string()),
            expires_at,
        )
        .unwrap();

        // Second rotation while first is still pending.
        let result = db.start_key_rotation(
            &card.id,
            &AgentId::from_raw("pending-new-2".to_string()),
            expires_at,
        );
        assert!(result.is_err(), "second rotation should be rejected");
    }

    #[test]
    fn start_key_rotation_card_not_found() {
        let db = test_db();
        let fake_card_id = AgentCardId::new_v4();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
        let result = db.start_key_rotation(
            &fake_card_id,
            &AgentId::from_raw("new-id".to_string()),
            expires_at,
        );
        assert!(result.is_err());
    }

    #[test]
    fn get_agent_group_id_pending_expired_not_returned() {
        let db = test_db();
        let (owner_id, group_id) = ensure_test_user(&db);
        let card = db
            .register(
                &make_reg("expired-rot-agent", "ExpiredRot", vec![]),
                owner_id,
                group_id,
            )
            .unwrap();

        // Set an already-expired rotation via raw SQL.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE agent_cards SET pending_agent_id = ?1, rotation_expires_at = ?2 WHERE id = ?3",
                params![
                    "expired-new-id",
                    "2000-01-01T00:00:00+00:00",
                    card.id.to_string(),
                ],
            )
            .unwrap();
        }

        // Expired pending key must NOT be returned.
        let found = db.get_agent_group_id("expired-new-id").unwrap();
        assert!(
            found.is_none(),
            "expired pending key should not be returned"
        );
    }
}
