//! SQLite-backed persistence layer for the registry.
//!
//! [`Database`] owns a single [`rusqlite::Connection`] guarded by a
//! [`Mutex`] and exposes domain-scoped methods implemented across the
//! submodules below: [`agents`] (agent card CRUD + search), [`users`],
//! [`tokens`] (API tokens), [`groups`] (groups + membership), [`setup_keys`],
//! [`acl`] (ACL rules), [`revocations`], [`rotation`] (key rotation
//! workflow), and [`sync`] (sync snapshot assembly). Schema creation and
//! migration live here since they are shared setup, not domain-specific.

use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

mod acl;
mod agents;
mod groups;
mod revocations;
mod rotation;
mod setup_keys;
mod sync;
mod tokens;
mod users;

pub use acl::AclRuleRow;
pub use revocations::RevocationRow;
pub use rotation::RotationResult;

/// SQLite-backed persistence handle. Domain methods (users, groups, agent
/// cards, ACL, setup keys, revocations, key rotation) are implemented on
/// this type across the submodules of [`crate::db`].
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) the SQLite database at `path` and apply schema
    /// migrations. `path` may be `":memory:"` for an ephemeral database.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::agent_card::{AgentCardQuery, AgentCardRegistration, Capability};
    use agent_mesh_core::identity::{AclRuleId, AgentCardId, AgentId, GroupId, UserId};
    use agent_mesh_core::user::{
        ApiToken, Group, GroupMember, GroupRole, SetupKey, SetupKeyUsage, User,
    };
    use rusqlite::params;
    use uuid::Uuid;

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
            id: AclRuleId::from_raw(uuid::Uuid::new_v4().to_string()),
            group_id,
            source: AgentId::from_raw("agent-src".to_string()),
            target: AgentId::from_raw("agent-dst".to_string()),
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
        assert_eq!(rules[0].source.as_str(), "agent-src");
        assert_eq!(rules[0].target.as_str(), "agent-dst");
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
        let deleted = db
            .delete_acl_rule(
                &AclRuleId::from_raw("nonexistent-id".to_string()),
                &group_id,
            )
            .unwrap();
        assert!(!deleted);
    }

    // ── Revocation DAO tests ──────────────────────────────────────────────────

    fn make_revocation_row(agent_id: &str, revoked_by: UserId) -> RevocationRow {
        RevocationRow {
            agent_id: AgentId::from_raw(agent_id.to_string()),
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
        assert_eq!(revs[0].agent_id.as_str(), "agent-revoked-1");
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

        assert!(db
            .is_revoked(&AgentId::from_raw("agent-to-check".to_string()))
            .unwrap());
    }

    #[test]
    fn is_revoked_false() {
        let db = test_db();
        assert!(!db
            .is_revoked(&AgentId::from_raw("unknown-agent".to_string()))
            .unwrap());
    }

    #[test]
    fn create_revocation_upsert() {
        // PRIMARY KEY is agent_id: second insert with same agent_id should replace.
        let db = test_db();
        let (user_id, _) = ensure_test_user(&db);
        let rev1 = make_revocation_row("dup-agent", user_id);
        db.create_revocation(&rev1).unwrap();

        let rev2 = RevocationRow {
            agent_id: AgentId::from_raw("dup-agent".to_string()),
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

        let found = db
            .get_agent_group_id(&AgentId::from_raw("lookup-agent".to_string()))
            .unwrap();
        assert_eq!(found, Some(group_id));
    }

    #[test]
    fn get_agent_group_id_not_found() {
        let db = test_db();
        let found = db
            .get_agent_group_id(&AgentId::from_raw("ghost-agent".to_string()))
            .unwrap();
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
        let found = db
            .get_agent_group_id(&AgentId::from_raw("new-agent-id".to_string()))
            .unwrap();
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
        let found = db
            .get_agent_group_id(&AgentId::from_raw("expired-new-id".to_string()))
            .unwrap();
        assert!(
            found.is_none(),
            "expired pending key should not be returned"
        );
    }
}
