use std::collections::HashSet;
use std::sync::Arc;

use agent_mesh_core::acl::AclPolicy;
use agent_mesh_core::agent_card::AgentCard;
use agent_mesh_core::identity::AgentId;
use agent_mesh_core::sync::SyncEvent;
use futures_util::StreamExt;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

use crate::node::NodeState;

/// CP Sync WebSocket reconnect loop.
///
/// Runs indefinitely: connects to `cp_url/sync?agent_id=...`, receives
/// `SyncEvent` JSON messages and applies them to local state.
///
/// On disconnect (whether graceful or error), transitions `node_state` back to
/// `Authenticated` before sleeping 3 s and reconnecting.
pub async fn cp_sync_loop(
    cp_url: &str,
    bearer_token: Arc<RwLock<Option<String>>>,
    agent_id: &AgentId,
    acl: Arc<RwLock<AclPolicy>>,
    peers: Arc<RwLock<Vec<AgentCard>>>,
    revoked_keys: Arc<RwLock<HashSet<String>>>,
    node_state: Arc<RwLock<NodeState>>,
) -> anyhow::Result<()> {
    let mut first_no_token = true;

    loop {
        match connect_and_sync(
            cp_url,
            &bearer_token,
            agent_id,
            &acl,
            &peers,
            &revoked_keys,
            &node_state,
            &mut first_no_token,
        )
        .await
        {
            Ok(()) => tracing::info!("CP sync connection closed, reconnecting..."),
            Err(e) => tracing::warn!(error = %e, "CP sync error, reconnecting..."),
        }

        // Revert state on CP disconnect: Connected/Syncing → Authenticated.
        {
            let mut s = node_state.write().await;
            if *s == NodeState::Connected || *s == NodeState::Syncing {
                *s = NodeState::Authenticated;
                tracing::info!("CP sync disconnected, state → Authenticated");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Establish one WS session to the CP sync endpoint and process messages until
/// the connection closes or an error occurs.
#[allow(clippy::too_many_arguments)]
async fn connect_and_sync(
    cp_url: &str,
    bearer_token: &Arc<RwLock<Option<String>>>,
    agent_id: &AgentId,
    acl: &Arc<RwLock<AclPolicy>>,
    peers: &Arc<RwLock<Vec<AgentCard>>>,
    revoked_keys: &Arc<RwLock<HashSet<String>>>,
    node_state: &Arc<RwLock<NodeState>>,
    first_no_token: &mut bool,
) -> anyhow::Result<()> {
    // Read bearer token; retry with info/debug log if absent.
    let token = {
        let guard = bearer_token.read().await;
        match guard.clone() {
            Some(t) => {
                *first_no_token = true; // reset so next absence logs info again
                t
            }
            None => {
                if *first_no_token {
                    tracing::info!("waiting for authentication before CP sync");
                    *first_no_token = false;
                } else {
                    tracing::debug!("still waiting for authentication before CP sync");
                }
                return Err(anyhow::anyhow!("no bearer token"));
            }
        }
    };

    // Build WS URL: ws(s)://.../sync?agent_id=...
    let ws_url = build_ws_url(cp_url, agent_id)?;

    let mut req = ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid WS request: {e}"))?;
    req.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid auth header value: {e}"))?,
    );

    tracing::info!(url = ws_url, "connecting to CP sync endpoint");
    let (ws_stream, _) = tokio_tungstenite::connect_async(req).await?;

    // Transition Authenticated → Syncing on successful connection.
    {
        let mut s = node_state.write().await;
        if *s == NodeState::Authenticated {
            *s = NodeState::Syncing;
            tracing::info!("CP sync connected, state → Syncing");
        }
    }

    let (_, mut rx) = ws_stream.split();

    while let Some(msg) = rx.next().await {
        match msg? {
            Message::Text(text) => match serde_json::from_str::<SyncEvent>(&text) {
                Ok(event) => {
                    apply_sync_event(event, acl, peers, revoked_keys).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "CP sync: failed to parse SyncEvent, skipping");
                }
            },
            Message::Close(_) => {
                tracing::info!("CP sync: server closed connection");
                break;
            }
            // Ping/Pong/Binary — ignore.
            _ => {}
        }
    }

    Ok(())
}

/// Apply a single `SyncEvent` to the local state stores.
async fn apply_sync_event(
    event: SyncEvent,
    acl: &Arc<RwLock<AclPolicy>>,
    peers: &Arc<RwLock<Vec<AgentCard>>>,
    revoked_keys: &Arc<RwLock<HashSet<String>>>,
) {
    match event {
        SyncEvent::FullSync(msg) => {
            tracing::debug!(seq = msg.seq, "CP sync: FullSync received");

            // Replace ACL rules.
            {
                let mut acl_guard = acl.write().await;
                acl_guard.rules = msg.acl_rules;
            }

            // Replace peers.
            {
                let mut peers_guard = peers.write().await;
                *peers_guard = msg.peers;
            }

            // Replace revoked keys.
            {
                let mut rk_guard = revoked_keys.write().await;
                *rk_guard = msg
                    .revoked_keys
                    .into_iter()
                    .map(|r| r.agent_id.as_str().to_string())
                    .collect();
            }
        }

        SyncEvent::PeerAdded(card) => {
            tracing::debug!(agent_id = card.agent_id.as_str(), "CP sync: PeerAdded");
            let mut peers_guard = peers.write().await;
            // Replace existing entry if present (same agent_id).
            if let Some(pos) = peers_guard.iter().position(|p| p.agent_id == card.agent_id) {
                peers_guard[pos] = card;
            } else {
                peers_guard.push(card);
            }
        }

        SyncEvent::PeerRemoved(agent_id) => {
            tracing::debug!(agent_id = agent_id.as_str(), "CP sync: PeerRemoved");
            let mut peers_guard = peers.write().await;
            peers_guard.retain(|p| p.agent_id != agent_id);
        }

        SyncEvent::AclUpdated(rules) => {
            tracing::debug!(count = rules.len(), "CP sync: AclUpdated");
            let mut acl_guard = acl.write().await;
            acl_guard.rules = rules;
        }

        SyncEvent::KeyRevoked(rev) => {
            tracing::debug!(agent_id = rev.agent_id.as_str(), "CP sync: KeyRevoked");
            let mut rk_guard = revoked_keys.write().await;
            rk_guard.insert(rev.agent_id.as_str().to_string());
        }

        SyncEvent::KeyRotated {
            card_id,
            old_agent_id,
            new_agent_id,
        } => {
            tracing::debug!(
                card_id = %card_id,
                old = old_agent_id.as_str(),
                new = new_agent_id.as_str(),
                "CP sync: KeyRotated"
            );
            // Own rotation is already applied by local_api /rotate/complete.
            // Here we update peers for rotations of other agents in the group.
            let mut peers_guard = peers.write().await;
            for card in peers_guard.iter_mut() {
                if card.agent_id == old_agent_id {
                    card.agent_id = new_agent_id.clone();
                }
            }
        }

        SyncEvent::AgentOnline(agent_id) => {
            tracing::info!(agent_id = agent_id.as_str(), "CP sync: AgentOnline");
            let mut peers_guard = peers.write().await;
            if let Some(card) = peers_guard.iter_mut().find(|p| p.agent_id == agent_id) {
                card.online = Some(true);
            }
        }

        SyncEvent::AgentOffline(agent_id) => {
            tracing::info!(agent_id = agent_id.as_str(), "CP sync: AgentOffline");
            let mut peers_guard = peers.write().await;
            if let Some(card) = peers_guard.iter_mut().find(|p| p.agent_id == agent_id) {
                card.online = Some(false);
            }
        }
    }
}

/// Convert an HTTP(S) CP URL to a WS(S) URL with `agent_id` query param.
///
/// Returns the URL as a `String`; `connect_async` accepts anything that
/// implements `IntoClientRequest`, including `&str`.
fn build_ws_url(cp_url: &str, agent_id: &AgentId) -> anyhow::Result<String> {
    let base = cp_url.trim_end_matches('/');

    // Replace scheme: https → wss, http → ws.
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        // Already ws:// / wss:// or unknown — pass through.
        base.to_string()
    };

    Ok(format!("{ws_base}/sync?agent_id={}", agent_id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::acl::AclRule;
    use agent_mesh_core::identity::AgentKeypair;
    use agent_mesh_core::message::KeyRevocation;
    use agent_mesh_core::sync::{RelayEndpoint, SyncMessage};

    fn make_agent_id() -> AgentId {
        AgentKeypair::generate().agent_id()
    }

    fn empty_acl() -> Arc<RwLock<AclPolicy>> {
        Arc::new(RwLock::new(AclPolicy::default()))
    }

    fn empty_peers() -> Arc<RwLock<Vec<AgentCard>>> {
        Arc::new(RwLock::new(Vec::new()))
    }

    fn empty_revoked() -> Arc<RwLock<HashSet<String>>> {
        Arc::new(RwLock::new(HashSet::new()))
    }

    // ── build_ws_url ──────────────────────────────────────────────────────────

    #[test]
    fn build_ws_url_converts_https() {
        let id = make_agent_id();
        let url = build_ws_url("https://cp.example.com", &id).unwrap();
        assert!(url.starts_with("wss://cp.example.com/sync?agent_id="));
    }

    #[test]
    fn build_ws_url_converts_http() {
        let id = make_agent_id();
        let url = build_ws_url("http://cp.local:8080", &id).unwrap();
        assert!(url.starts_with("ws://cp.local:8080/sync?agent_id="));
    }

    #[test]
    fn build_ws_url_strips_trailing_slash() {
        let id = make_agent_id();
        let url = build_ws_url("http://cp.local/", &id).unwrap();
        // Should not have double slash before /sync.
        assert!(!url.contains("//sync"), "double slash: {url}");
    }

    // ── apply_sync_event: FullSync ────────────────────────────────────────────

    #[tokio::test]
    async fn full_sync_replaces_state() {
        use agent_mesh_core::acl::AclRule;

        let acl = empty_acl();
        let peers = empty_peers();
        let revoked = empty_revoked();

        let src = make_agent_id();
        let tgt = make_agent_id();

        let msg = SyncMessage {
            peers: vec![],
            acl_rules: vec![AclRule {
                source: src.clone(),
                target: tgt.clone(),
                allowed_capabilities: vec!["cap1".into()],
            }],
            revoked_keys: vec![],
            relay_endpoints: vec![RelayEndpoint {
                url: "wss://r.test".into(),
                region: None,
            }],
            seq: 1,
        };

        apply_sync_event(SyncEvent::FullSync(msg), &acl, &peers, &revoked).await;

        let acl_guard = acl.read().await;
        assert_eq!(acl_guard.rules.len(), 1);
        assert_eq!(acl_guard.rules[0].source, src);
    }

    #[tokio::test]
    async fn full_sync_replaces_revoked_keys() {
        let acl = empty_acl();
        let peers = empty_peers();
        let revoked = empty_revoked();

        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, None);
        let expected_id = kp.agent_id().as_str().to_string();

        let msg = SyncMessage {
            peers: vec![],
            acl_rules: vec![],
            revoked_keys: vec![rev],
            relay_endpoints: vec![],
            seq: 2,
        };

        apply_sync_event(SyncEvent::FullSync(msg), &acl, &peers, &revoked).await;

        let rk = revoked.read().await;
        assert!(
            rk.contains(&expected_id),
            "revoked key missing: {expected_id}"
        );
    }

    // ── apply_sync_event: AclUpdated ─────────────────────────────────────────

    #[tokio::test]
    async fn acl_updated_replaces_rules() {
        let acl = empty_acl();
        let peers = empty_peers();
        let revoked = empty_revoked();

        let src = make_agent_id();
        let tgt = make_agent_id();
        let rules = vec![AclRule {
            source: src.clone(),
            target: tgt.clone(),
            allowed_capabilities: vec!["cap".into()],
        }];

        apply_sync_event(SyncEvent::AclUpdated(rules), &acl, &peers, &revoked).await;

        let guard = acl.read().await;
        assert_eq!(guard.rules.len(), 1);
        assert_eq!(guard.rules[0].source, src);
    }

    // ── apply_sync_event: KeyRevoked ─────────────────────────────────────────

    #[tokio::test]
    async fn key_revoked_inserts_agent_id() {
        let acl = empty_acl();
        let peers = empty_peers();
        let revoked = empty_revoked();

        let kp = AgentKeypair::generate();
        let rev = KeyRevocation::new(&kp, None);
        let expected_id = kp.agent_id().as_str().to_string();

        apply_sync_event(SyncEvent::KeyRevoked(rev), &acl, &peers, &revoked).await;

        let rk = revoked.read().await;
        assert!(rk.contains(&expected_id));
    }

    // ── apply_sync_event: KeyRotated ─────────────────────────────────────────

    fn make_agent_card(agent_id: agent_mesh_core::identity::AgentId) -> AgentCard {
        use agent_mesh_core::identity::{AgentCardId, GroupId, UserId};
        AgentCard {
            id: AgentCardId::new_v4(),
            agent_id,
            owner_id: UserId::new_v4(),
            group_id: GroupId::new_v4(),
            name: "test".into(),
            description: None,
            capabilities: vec![],
            registered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: None,
            online: None,
        }
    }

    #[tokio::test]
    async fn key_rotated_updates_peer_agent_id() {
        use agent_mesh_core::identity::AgentCardId;

        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let card_id = AgentCardId::new_v4();

        let mut card = make_agent_card(old_kp.agent_id());
        card.id = card_id;

        let acl = empty_acl();
        let peers = Arc::new(RwLock::new(vec![card]));
        let revoked = empty_revoked();

        apply_sync_event(
            SyncEvent::KeyRotated {
                card_id,
                old_agent_id: old_kp.agent_id(),
                new_agent_id: new_kp.agent_id(),
            },
            &acl,
            &peers,
            &revoked,
        )
        .await;

        let peers_guard = peers.read().await;
        assert_eq!(peers_guard.len(), 1);
        assert_eq!(peers_guard[0].agent_id, new_kp.agent_id());
    }

    #[tokio::test]
    async fn key_rotated_does_not_affect_unrelated_peers() {
        use agent_mesh_core::identity::AgentCardId;

        let peer_kp = AgentKeypair::generate();
        let old_kp = AgentKeypair::generate();
        let new_kp = AgentKeypair::generate();
        let card_id = AgentCardId::new_v4();

        // Unrelated peer that should NOT be updated.
        let unrelated = make_agent_card(peer_kp.agent_id());

        let acl = empty_acl();
        let peers = Arc::new(RwLock::new(vec![unrelated]));
        let revoked = empty_revoked();

        apply_sync_event(
            SyncEvent::KeyRotated {
                card_id,
                old_agent_id: old_kp.agent_id(),
                new_agent_id: new_kp.agent_id(),
            },
            &acl,
            &peers,
            &revoked,
        )
        .await;

        let peers_guard = peers.read().await;
        // Unrelated peer's agent_id must be unchanged.
        assert_eq!(peers_guard[0].agent_id, peer_kp.agent_id());
    }

    // ── NodeState transition logic ────────────────────────────────────────────

    #[test]
    fn node_state_variants_are_all_present() {
        // Ensure all 4 variants can be constructed and compared.
        assert_eq!(NodeState::Started, NodeState::Started);
        assert_eq!(NodeState::Authenticated, NodeState::Authenticated);
        assert_eq!(NodeState::Syncing, NodeState::Syncing);
        assert_eq!(NodeState::Connected, NodeState::Connected);
        assert_ne!(NodeState::Syncing, NodeState::Connected);
    }

    #[tokio::test]
    async fn authenticated_transitions_to_syncing_on_connect() {
        // Simulate the state transition that connect_and_sync performs.
        let node_state = Arc::new(RwLock::new(NodeState::Authenticated));
        {
            let mut s = node_state.write().await;
            if *s == NodeState::Authenticated {
                *s = NodeState::Syncing;
            }
        }
        assert_eq!(*node_state.read().await, NodeState::Syncing);
    }

    #[tokio::test]
    async fn syncing_transitions_to_authenticated_on_disconnect() {
        // Simulate the post-loop state transition in cp_sync_loop.
        let node_state = Arc::new(RwLock::new(NodeState::Syncing));
        {
            let mut s = node_state.write().await;
            if *s == NodeState::Connected || *s == NodeState::Syncing {
                *s = NodeState::Authenticated;
            }
        }
        assert_eq!(*node_state.read().await, NodeState::Authenticated);
    }

    #[tokio::test]
    async fn connected_transitions_to_authenticated_on_cp_disconnect() {
        let node_state = Arc::new(RwLock::new(NodeState::Connected));
        {
            let mut s = node_state.write().await;
            if *s == NodeState::Connected || *s == NodeState::Syncing {
                *s = NodeState::Authenticated;
            }
        }
        assert_eq!(*node_state.read().await, NodeState::Authenticated);
    }

    // ── apply_sync_event: AgentOnline / AgentOffline ─────────────────────────

    #[tokio::test]
    async fn agent_online_updates_peer_card() {
        let kp = AgentKeypair::generate();
        let card = make_agent_card(kp.agent_id());

        let acl = empty_acl();
        let peers = Arc::new(RwLock::new(vec![card]));
        let revoked = empty_revoked();

        apply_sync_event(
            SyncEvent::AgentOnline(kp.agent_id()),
            &acl,
            &peers,
            &revoked,
        )
        .await;

        let peers_guard = peers.read().await;
        assert_eq!(peers_guard[0].online, Some(true));
    }

    #[tokio::test]
    async fn agent_offline_updates_peer_card() {
        let kp = AgentKeypair::generate();
        let mut card = make_agent_card(kp.agent_id());
        card.online = Some(true);

        let acl = empty_acl();
        let peers = Arc::new(RwLock::new(vec![card]));
        let revoked = empty_revoked();

        apply_sync_event(
            SyncEvent::AgentOffline(kp.agent_id()),
            &acl,
            &peers,
            &revoked,
        )
        .await;

        let peers_guard = peers.read().await;
        assert_eq!(peers_guard[0].online, Some(false));
    }

    #[tokio::test]
    async fn agent_online_unknown_peer_is_noop() {
        let known_kp = AgentKeypair::generate();
        let unknown_kp = AgentKeypair::generate();
        let card = make_agent_card(known_kp.agent_id());

        let acl = empty_acl();
        let peers = Arc::new(RwLock::new(vec![card]));
        let revoked = empty_revoked();

        // Should not panic even when the agent_id is unknown.
        apply_sync_event(
            SyncEvent::AgentOnline(unknown_kp.agent_id()),
            &acl,
            &peers,
            &revoked,
        )
        .await;

        let peers_guard = peers.read().await;
        // Known peer remains untouched.
        assert_eq!(peers_guard[0].online, None);
    }
}
