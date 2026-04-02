//! User, Group, and token types for the v0.2 user model.
//!
//! # Key Separation Principle
//!
//! All keys, tokens, and secrets used in agent-mesh serve a single purpose only.
//! Mixing keys across purposes is forbidden.
//!
//! **Best-practice basis**: Tailscale manages node key, machine key, auth key,
//! API access token, and OAuth client secret as separate entities. NetBird
//! similarly separates WireGuard key, setup key, and PAT.
//!
//! | Key | Type / Location | Purpose | Generated | Stored | Lifetime |
//! |---|---|---|---|---|---|
//! | AgentKeypair (Ed25519) | `identity.rs` | Relay auth & message signing | `meshctl keygen` | `~/.mesh/keys/` | Persistent (until revocation) |
//! | NoiseKeypair (X25519) | `noise.rs` | Agent-to-agent E2E encryption (Noise Protocol) | meshd at startup | Memory only | Process lifetime |
//! | ApiToken (Bearer) | `user.rs` | Control-plane HTTP API auth | On OAuth completion | `~/.mesh/config.toml` (0600) | Time-limited |
//! | SetupKey | `user.rs` | Non-interactive agent registration | Issued by CP | Environment variable (recommended) | Time-limited + use count |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::{GroupId, UserId};

/// A user authenticated via OAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    /// Provider-scoped external identifier, e.g. `"github:12345"`.
    pub external_id: String,
    /// OAuth provider name, e.g. `"github"` or `"google"`.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Visibility and communication boundary for a set of agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    /// The user who created this group.
    pub created_by: UserId,
    pub created_at: DateTime<Utc>,
}

/// Association between a user and a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub user_id: UserId,
    pub role: GroupRole,
}

/// Permission level of a user within a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

/// API authentication token.
///
/// The plaintext is shown only once at issuance; the database stores the
/// SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    /// SHA-256 hash of the raw token.
    pub token_hash: String,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Non-interactive node registration key (for CI/CD and headless environments).
///
/// Inspired by Tailscale Auth Key and NetBird Setup Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupKey {
    /// Unique ID for this setup key.
    ///
    /// Plain `Uuid` is used here instead of a Newtype because setup keys are
    /// never mixed with other ID types (architecture.md §3.3).
    pub id: Uuid,
    /// SHA-256 hash of the raw key (plaintext shown only at issuance).
    pub key_hash: String,
    /// The user who issued this key. Agents registered via this key are
    /// attributed to this user.
    pub user_id: UserId,
    /// Agents registered via this key are automatically placed in this group.
    pub group_id: GroupId,
    pub usage: SetupKeyUsage,
    /// Remaining uses for a `Reusable` key; `None` for `OneOff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses_remaining: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Usage policy for a [`SetupKey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetupKeyUsage {
    /// Single-use; automatically invalidated after one registration.
    OneOff,
    /// Can be used up to `max_uses` times.
    Reusable { max_uses: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fixed_user_id() -> UserId {
        UserId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    fn fixed_group_id() -> GroupId {
        GroupId::parse_str("00000000-0000-0000-0000-000000000002").unwrap()
    }

    fn fixed_time() -> DateTime<Utc> {
        "2024-01-01T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn user_json_roundtrip() {
        let user = User {
            id: fixed_user_id(),
            external_id: "github:12345".to_string(),
            provider: "github".to_string(),
            display_name: Some("Alice".to_string()),
            created_at: fixed_time(),
        };
        let json = serde_json::to_string(&user).unwrap();
        let decoded: User = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, user.id);
        assert_eq!(decoded.external_id, user.external_id);
        assert_eq!(decoded.provider, user.provider);
        assert_eq!(decoded.display_name, user.display_name);
    }

    #[test]
    fn group_json_roundtrip() {
        let group = Group {
            id: fixed_group_id(),
            name: "engineering".to_string(),
            created_by: fixed_user_id(),
            created_at: fixed_time(),
        };
        let json = serde_json::to_string(&group).unwrap();
        let decoded: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, group.id);
        assert_eq!(decoded.name, group.name);
        assert_eq!(decoded.created_by, group.created_by);
    }

    #[test]
    fn group_member_json_roundtrip() {
        let member = GroupMember {
            group_id: fixed_group_id(),
            user_id: fixed_user_id(),
            role: GroupRole::Admin,
        };
        let json = serde_json::to_string(&member).unwrap();
        let decoded: GroupMember = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.group_id, member.group_id);
        assert_eq!(decoded.user_id, member.user_id);
        assert_eq!(decoded.role, GroupRole::Admin);

        // Verify all GroupRole variants round-trip correctly.
        for role in [GroupRole::Owner, GroupRole::Admin, GroupRole::Member] {
            let json = serde_json::to_string(&role).unwrap();
            let decoded: GroupRole = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, role);
        }
    }

    #[test]
    fn api_token_json_roundtrip() {
        let token = ApiToken {
            token_hash: "abc123hash".to_string(),
            user_id: fixed_user_id(),
            created_at: fixed_time(),
            expires_at: Some(fixed_time()),
        };
        let json = serde_json::to_string(&token).unwrap();
        let decoded: ApiToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.token_hash, token.token_hash);
        assert_eq!(decoded.user_id, token.user_id);
        assert_eq!(decoded.expires_at, token.expires_at);
    }

    #[test]
    fn setup_key_json_roundtrip() {
        // OneOff variant
        let key_oneoff = SetupKey {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap(),
            key_hash: "deadbeef".to_string(),
            user_id: fixed_user_id(),
            group_id: fixed_group_id(),
            usage: SetupKeyUsage::OneOff,
            uses_remaining: None,
            created_at: fixed_time(),
            expires_at: fixed_time(),
        };
        let json = serde_json::to_string(&key_oneoff).unwrap();
        let decoded: SetupKey = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, key_oneoff.id);
        assert_eq!(decoded.usage, SetupKeyUsage::OneOff);
        assert!(decoded.uses_remaining.is_none());

        // Reusable variant — verify externally tagged format {"Reusable":{"max_uses":5}}
        let key_reusable = SetupKey {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000098").unwrap(),
            key_hash: "cafebabe".to_string(),
            user_id: fixed_user_id(),
            group_id: fixed_group_id(),
            usage: SetupKeyUsage::Reusable { max_uses: 5 },
            uses_remaining: Some(5),
            created_at: fixed_time(),
            expires_at: fixed_time(),
        };
        let json = serde_json::to_string(&key_reusable).unwrap();
        assert!(
            json.contains(r#""Reusable""#),
            "Reusable variant must be externally tagged: {json}"
        );
        assert!(
            json.contains(r#""max_uses":5"#),
            "max_uses field must be present: {json}"
        );
        let decoded: SetupKey = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.usage, SetupKeyUsage::Reusable { max_uses: 5 });
        assert_eq!(decoded.uses_remaining, Some(5));
    }
}
