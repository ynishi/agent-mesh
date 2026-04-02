use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::Mutex;

use agent_mesh_core::identity::{AgentId, GroupId};
use agent_mesh_core::sync::SyncEvent;

use crate::auth::AuthUser;
use crate::AppState;

/// Shared, async-safe handle to a WebSocket sink.
type SinkHandle = Arc<Mutex<SplitSink<WebSocket, Message>>>;

/// A single WebSocket connection registered with the hub.
struct SyncConnection {
    group_id: GroupId,
    /// `SinkHandle` allows cloning the handle out of the RwLock-guarded map
    /// so we can release the read lock before calling the async `send()`.
    sink: SinkHandle,
}

/// Group-scoped WebSocket broadcast hub.
///
/// Maintains an in-memory registry of connected agents and their group membership,
/// enabling efficient fan-out of `SyncEvent` messages to all agents in a group.
///
/// Thread safety: `connections` and `group_index` are guarded by `std::sync::RwLock`
/// for their metadata (AgentId → GroupId mapping). The actual sink write is gated
/// by `Arc<tokio::sync::Mutex>` per connection — the Arc is cloned while holding
/// the read lock, then the lock is released before any await point.
pub struct SyncHub {
    connections: RwLock<HashMap<AgentId, SyncConnection>>,
    group_index: RwLock<HashMap<GroupId, HashSet<AgentId>>>,
}

impl SyncHub {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            group_index: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new WebSocket connection for an agent.
    pub async fn register(
        &self,
        agent_id: AgentId,
        group_id: GroupId,
        sink: SplitSink<WebSocket, Message>,
    ) {
        {
            let mut conns = match self.connections.write() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("connections write lock poisoned: {e}");
                    return;
                }
            };
            conns.insert(
                agent_id.clone(),
                SyncConnection {
                    group_id,
                    sink: Arc::new(Mutex::new(sink)),
                },
            );
        }
        {
            let mut idx = match self.group_index.write() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("group_index write lock poisoned: {e}");
                    return;
                }
            };
            idx.entry(group_id).or_default().insert(agent_id);
        }
    }

    /// Unregister a WebSocket connection. No-op if the agent is not registered.
    pub async fn unregister(&self, agent_id: &AgentId) {
        let group_id = {
            let mut conns = match self.connections.write() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("connections write lock poisoned during unregister: {e}");
                    return;
                }
            };
            conns.remove(agent_id).map(|c| c.group_id)
        };
        if let Some(gid) = group_id {
            let mut idx = match self.group_index.write() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("group_index write lock poisoned during unregister: {e}");
                    return;
                }
            };
            if let Some(set) = idx.get_mut(&gid) {
                set.remove(agent_id);
                if set.is_empty() {
                    idx.remove(&gid);
                }
            }
        }
    }

    /// Broadcast a `SyncEvent` to all connected agents in a group.
    ///
    /// Serialization errors are logged and the broadcast is skipped.
    /// Send failures are treated as dead connections and unregistered.
    pub async fn broadcast_to_group(&self, group_id: &GroupId, event: &SyncEvent) {
        let json = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("SyncHub: failed to serialize SyncEvent: {e}");
                return;
            }
        };
        let msg = Message::Text(json.into());

        // Collect agent IDs in this group while holding the index read lock,
        // then release the lock before touching connections.
        let agent_ids: Vec<AgentId> = {
            let idx = match self.group_index.read() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("group_index read lock poisoned: {e}");
                    return;
                }
            };
            idx.get(group_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect()
        };

        // Collect Arc handles while holding the read lock, then release the lock
        // before any await point to avoid holding a non-Send guard across awaits.
        let sinks: Vec<(AgentId, SinkHandle)> = {
            let conns = match self.connections.read() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("connections read lock poisoned: {e}");
                    return;
                }
            };
            agent_ids
                .iter()
                .filter_map(|id| conns.get(id).map(|c| (id.clone(), Arc::clone(&c.sink))))
                .collect()
        };

        let mut dead = Vec::new();
        for (agent_id, sink_arc) in sinks {
            let mut sink = sink_arc.lock().await;
            if sink.send(msg.clone()).await.is_err() {
                dead.push(agent_id);
            }
        }

        for agent_id in dead {
            self.unregister(&agent_id).await;
        }
    }

    /// Return the set of all currently online agent IDs (across all groups).
    pub fn online_agents(&self) -> HashSet<AgentId> {
        match self.connections.read() {
            Ok(conns) => conns.keys().cloned().collect(),
            Err(e) => {
                tracing::error!("connections read lock poisoned in online_agents: {e}");
                HashSet::new()
            }
        }
    }
}

impl Default for SyncHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Query parameters for the `/sync` WebSocket endpoint.
#[derive(serde::Deserialize)]
pub struct SyncParams {
    pub agent_id: String,
}

/// `GET /sync` — WebSocket endpoint for state synchronization.
///
/// Requires Bearer authentication (via `require_auth` middleware).
/// The caller must provide `?agent_id=<agent-id>` as a query parameter.
///
/// On successful connection:
/// 1. Resolves the group for the given agent_id.
/// 2. Verifies the agent belongs to the authenticated user.
/// 3. Upgrades to WebSocket.
/// 4. Sends `SyncEvent::FullSync` immediately.
/// 5. Reads incoming frames (Ping/Pong maintenance) until Close.
/// 6. Unregisters on disconnect.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Query(params): Query<SyncParams>,
) -> impl IntoResponse {
    let agent_id = AgentId::from_raw(params.agent_id);

    // Resolve group_id and verify ownership before upgrading.
    let card_result = state
        .db
        .search(&agent_mesh_core::agent_card::AgentCardQuery {
            agent_id: Some(agent_id.clone()),
            ..Default::default()
        });

    let group_id = match card_result {
        Err(e) => {
            tracing::warn!(
                "ws_handler: db error resolving agent {}: {e}",
                agent_id.as_str()
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
        Ok(cards) if cards.is_empty() => {
            return (StatusCode::BAD_REQUEST, "agent not found").into_response();
        }
        Ok(cards) => {
            // Verify the agent belongs to the authenticated user.
            let card = &cards[0];
            if card.owner_id != user_id {
                return (StatusCode::FORBIDDEN, "agent not owned by this user").into_response();
            }
            card.group_id
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, agent_id, group_id))
}

async fn handle_socket(socket: WebSocket, state: AppState, agent_id: AgentId, group_id: GroupId) {
    let (sink, mut stream) = socket.split();

    state
        .sync_hub
        .register(agent_id.clone(), group_id, sink)
        .await;

    // Send full sync immediately after registration.
    match state.db.build_sync_message_for_group(&group_id) {
        Ok(msg) => {
            let event = SyncEvent::FullSync(msg);
            state.sync_hub.broadcast_to_group(&group_id, &event).await;
        }
        Err(e) => {
            tracing::warn!(
                "ws_handler: failed to build full sync for group {}: {e}",
                group_id.0
            );
        }
    }

    // Read loop: maintain Ping/Pong, exit on Close.
    while let Some(result) = stream.next().await {
        match result {
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) => {
                // axum's WebSocket layer auto-sends Pong; nothing to do here.
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(
                    "ws_handler: read error for agent {}: {e}",
                    agent_id.as_str()
                );
                break;
            }
        }
    }

    state.sync_hub.unregister(&agent_id).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::identity::AgentKeypair;

    fn make_group_id() -> GroupId {
        GroupId::new_v4()
    }

    fn make_agent_id() -> AgentId {
        AgentKeypair::generate().agent_id()
    }

    // Helper: create a dummy WebSocket split for testing.
    // We test register/unregister/online_agents without a real WS connection
    // by verifying the hub's index state.

    #[tokio::test]
    async fn online_agents_empty_at_start() {
        let hub = SyncHub::new();
        assert!(hub.online_agents().is_empty());
    }

    #[tokio::test]
    async fn unregister_nonexistent_is_noop() {
        let hub = SyncHub::new();
        let agent_id = make_agent_id();
        // Should not panic.
        hub.unregister(&agent_id).await;
        assert!(hub.online_agents().is_empty());
    }

    #[tokio::test]
    async fn broadcast_to_empty_group_is_noop() {
        let hub = SyncHub::new();
        let group_id = make_group_id();
        let msg = agent_mesh_core::sync::SyncMessage {
            peers: vec![],
            acl_rules: vec![],
            revoked_keys: vec![],
            relay_endpoints: vec![],
            seq: 0,
        };
        let event = SyncEvent::FullSync(msg);
        // Should not panic.
        hub.broadcast_to_group(&group_id, &event).await;
    }
}
