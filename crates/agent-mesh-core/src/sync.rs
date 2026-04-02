use serde::{Deserialize, Serialize};

use crate::acl::AclRule;
use crate::agent_card::AgentCard;
use crate::identity::AgentId;
use crate::message::KeyRevocation;

/// State snapshot distributed from the Control Plane to meshd instances.
///
/// Sent as `SyncEvent::FullSync` on initial connection and after significant
/// state changes. No IO or async dependencies — pure data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    /// Known agent cards in the group.
    pub peers: Vec<AgentCard>,
    /// ACL rules active in the group.
    pub acl_rules: Vec<AclRule>,
    /// Revoked agent keys.
    pub revoked_keys: Vec<KeyRevocation>,
    /// Relay endpoints available to this group.
    pub relay_endpoints: Vec<RelayEndpoint>,
    /// Monotonically increasing sequence number for ordering.
    pub seq: u64,
}

/// A relay server endpoint descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEndpoint {
    /// WebSocket URL of the relay (e.g. `wss://relay.example.com`).
    pub url: String,
    /// Optional geographic region hint (e.g. `"us-east-1"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Incremental or full state update events streamed from CP to meshd.
///
/// Uses adjacently-tagged representation `{"type": "...", "data": ...}` to
/// support newtype variants wrapping primitive types (e.g. `PeerRemoved(AgentId)`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SyncEvent {
    /// Full state snapshot; replace local state entirely.
    FullSync(SyncMessage),
    /// A new peer has registered.
    PeerAdded(AgentCard),
    /// A peer has deregistered or been removed.
    PeerRemoved(AgentId),
    /// ACL rules were updated (full replacement of the group's rules).
    AclUpdated(Vec<AclRule>),
    /// A key was revoked.
    KeyRevoked(KeyRevocation),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;

    #[test]
    fn relay_endpoint_serialization_roundtrip() {
        let ep = RelayEndpoint {
            url: "wss://relay.example.com".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let json = serde_json::to_string(&ep).expect("serialize");
        let de: RelayEndpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(de.url, ep.url);
        assert_eq!(de.region, ep.region);
    }

    #[test]
    fn relay_endpoint_region_omitted_when_none() {
        let ep = RelayEndpoint {
            url: "wss://relay.example.com".to_string(),
            region: None,
        };
        let json = serde_json::to_string(&ep).expect("serialize");
        assert!(!json.contains("region"), "region should be omitted: {json}");
    }

    #[test]
    fn sync_event_full_sync_roundtrip() {
        let msg = SyncMessage {
            peers: vec![],
            acl_rules: vec![],
            revoked_keys: vec![],
            relay_endpoints: vec![RelayEndpoint {
                url: "wss://r.example.com".to_string(),
                region: None,
            }],
            seq: 42,
        };
        let event = SyncEvent::FullSync(msg);
        let json = serde_json::to_string(&event).expect("serialize");
        let de: SyncEvent = serde_json::from_str(&json).expect("deserialize");
        match de {
            SyncEvent::FullSync(m) => assert_eq!(m.seq, 42),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn sync_event_peer_removed_roundtrip() {
        let kp = AgentKeypair::generate();
        let agent_id = kp.agent_id();
        let event = SyncEvent::PeerRemoved(agent_id.clone());
        let json = serde_json::to_string(&event).expect("serialize");
        let de: SyncEvent = serde_json::from_str(&json).expect("deserialize");
        match de {
            SyncEvent::PeerRemoved(id) => assert_eq!(id, agent_id),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn sync_event_key_revoked_roundtrip() {
        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, Some("test".to_string()));
        let event = SyncEvent::KeyRevoked(rev.clone());
        let json = serde_json::to_string(&event).expect("serialize");
        let de: SyncEvent = serde_json::from_str(&json).expect("deserialize");
        match de {
            SyncEvent::KeyRevoked(r) => {
                assert_eq!(r.agent_id, rev.agent_id);
                assert!(r.verify().is_ok());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
