//! `groups` and `group_members` tables: group creation, membership
//! management, and the auto-provisioning of a user's default group.

use agent_mesh_core::identity::{GroupId, UserId};
use agent_mesh_core::user::{Group, GroupMember, GroupRole};
use anyhow::Result;
use rusqlite::params;

use super::Database;

impl Database {
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

    // ── Group methods ─────────────────────────────────────────────────────────

    /// Insert a new group row.
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

    /// List all groups `user_id` is a member of.
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

    /// Insert a group membership row.
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

    /// Remove a user's membership in a group. Idempotent: no error if the
    /// membership does not exist.
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
