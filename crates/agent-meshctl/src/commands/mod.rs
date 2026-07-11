/// `agent-meshctl acl` — manage ACL rules via meshd's Local API.
pub mod acl;
/// `agent-meshctl deregister` — delete an agent card, direct to the control
/// plane (does not revoke the underlying key; see [`revoke`] for that).
pub mod deregister;
/// `agent-meshctl discover` — search the registry for peer agent cards,
/// direct to the control plane.
pub mod discover;
/// `agent-meshctl group` — manage groups and their membership via meshd's
/// Local API.
pub mod group;
/// `agent-meshctl keygen` — generate a new Ed25519 identity keypair
/// (offline, prints to stdout).
pub mod keygen;
/// `agent-meshctl login` — OAuth device-flow login direct to the control
/// plane (no meshd required).
pub mod login;
/// `agent-meshctl register` — register an agent card, direct to the control
/// plane, generating a keypair if none is provided.
pub mod register;
/// `agent-meshctl request` — send a capability request to a peer agent
/// through meshd's Local API.
pub mod request;
/// `agent-meshctl revoke` — revoke a peer's key via meshd (blocks the key
/// and disconnects every card sharing it).
pub mod revoke;
/// `agent-meshctl rotate` — rotate this identity's keypair via meshd
/// (two-phase: initiate, then complete).
pub mod rotate;
/// `agent-meshctl setup-key` — manage setup keys used for key-based
/// registration, via meshd's Local API.
pub mod setup_key;
/// `agent-meshctl status` — show local daemon connection/auth status via
/// meshd's Local API.
pub mod status;

pub use self::acl::{acl_create, acl_delete, acl_list};
pub use self::deregister::deregister;
pub use self::discover::discover;
pub use self::group::{group_add_member, group_create, group_list, group_remove_member};
pub use self::keygen::keygen;
pub use self::login::login;
pub use self::register::register;
pub use self::request::request;
pub use self::revoke::revoke;
pub use self::rotate::rotate;
pub use self::setup_key::{setup_key_create, setup_key_list, setup_key_revoke};
pub use self::status::status;

use agent_mesh_core::acl::AclRule;
use agent_mesh_core::identity::{AgentId, AgentKeypair};
use anyhow::{Context, Result};

/// Resolves the secret key from the provided argument or MESH_SECRET_KEY env variable.
pub fn resolve_secret_key(provided: Option<&str>) -> Result<AgentKeypair> {
    let hex_str = match provided {
        Some(s) => s.to_string(),
        None => std::env::var("MESH_SECRET_KEY")
            .context("no --secret-key provided and MESH_SECRET_KEY env not set")?,
    };
    let bytes = hex::decode(&hex_str).context("invalid hex in secret key")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes (64 hex chars)"))?;
    Ok(AgentKeypair::from_bytes(&arr))
}

/// Outputs an ACL rule as JSON to stdout (offline, no meshd required).
pub fn acl_json(source_id: &str, target_id: &str, allow_csv: &str) -> Result<()> {
    let rule = AclRule {
        source: AgentId::from_raw(source_id.to_string()),
        target: AgentId::from_raw(target_id.to_string()),
        allowed_capabilities: allow_csv.split(',').map(|s| s.trim().to_string()).collect(),
    };
    println!("{}", serde_json::to_string_pretty(&rule)?);
    Ok(())
}

/// Builds an ACL rule value (testable version without stdout).
pub fn build_acl_rule(source_id: &str, target_id: &str, allow_csv: &str) -> AclRule {
    AclRule {
        source: AgentId::from_raw(source_id.to_string()),
        target: AgentId::from_raw(target_id.to_string()),
        allowed_capabilities: allow_csv.split(',').map(|s| s.trim().to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_secret_hex() -> String {
        let kp = AgentKeypair::generate();
        hex::encode(kp.secret_bytes())
    }

    #[test]
    fn resolve_secret_key_from_arg() {
        let hex = valid_secret_hex();
        let kp = resolve_secret_key(Some(&hex)).unwrap();
        assert!(!kp.agent_id().as_str().is_empty());
    }

    #[test]
    fn resolve_secret_key_invalid_hex() {
        let result = resolve_secret_key(Some("not-hex"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_secret_key_wrong_length() {
        let result = resolve_secret_key(Some("abcd"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_secret_key_no_arg_no_env() {
        std::env::remove_var("MESH_SECRET_KEY");
        let result = resolve_secret_key(None);
        assert!(result.is_err());
    }

    #[test]
    fn build_acl_rule_single_capability() {
        let rule = build_acl_rule("alice-id", "bob-id", "scheduling");
        assert_eq!(rule.source.as_str(), "alice-id");
        assert_eq!(rule.target.as_str(), "bob-id");
        assert_eq!(rule.allowed_capabilities, vec!["scheduling"]);
    }

    #[test]
    fn build_acl_rule_multiple_capabilities() {
        let rule = build_acl_rule("alice", "bob", "scheduling, availability, contact");
        assert_eq!(rule.allowed_capabilities.len(), 3);
        assert_eq!(rule.allowed_capabilities[0], "scheduling");
        assert_eq!(rule.allowed_capabilities[1], "availability");
        assert_eq!(rule.allowed_capabilities[2], "contact");
    }

    #[test]
    fn acl_json_roundtrip() {
        let rule = build_acl_rule("src", "tgt", "cap1,cap2");
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: AclRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source.as_str(), "src");
        assert_eq!(parsed.target.as_str(), "tgt");
        assert_eq!(parsed.allowed_capabilities, vec!["cap1", "cap2"]);
    }
}
