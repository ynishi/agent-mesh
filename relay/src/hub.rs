use std::collections::HashMap;
use std::sync::Arc;

use futures_util::stream::SplitSink;
use futures_util::SinkExt;
use mesh_proto::identity::AgentId;
use mesh_proto::message::MeshEnvelope;
use tokio::sync::{Mutex, RwLock};

type WsSink = SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>;

/// Connected agent session.
struct AgentSession {
    sink: Mutex<WsSink>,
}

/// Central hub that routes messages between connected agents.
pub struct Hub {
    agents: RwLock<HashMap<String, Arc<AgentSession>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
        }
    }

    /// Register a connected agent's WebSocket sink.
    pub async fn register(&self, agent_id: &AgentId, sink: WsSink) {
        let session = Arc::new(AgentSession {
            sink: Mutex::new(sink),
        });
        let mut agents = self.agents.write().await;
        agents.insert(agent_id.as_str().to_string(), session);
        tracing::info!(agent = agent_id.as_str(), "agent registered");
    }

    /// Remove a disconnected agent.
    pub async fn unregister(&self, agent_id: &AgentId) {
        let mut agents = self.agents.write().await;
        agents.remove(agent_id.as_str());
        tracing::info!(agent = agent_id.as_str(), "agent unregistered");
    }

    /// Route an envelope to the destination agent.
    /// Returns Ok(true) if delivered, Ok(false) if target not connected.
    pub async fn route(&self, envelope: &MeshEnvelope) -> Result<bool, String> {
        let agents = self.agents.read().await;
        let target_key = envelope.to.as_str();
        if let Some(session) = agents.get(target_key) {
            let json = serde_json::to_string(envelope).map_err(|e| format!("serialize: {e}"))?;
            let mut sink = session.sink.lock().await;
            sink.send(axum::extract::ws::Message::text(json))
                .await
                .map_err(|e| format!("send: {e}"))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Number of connected agents. Used by health/metrics endpoints.
    #[allow(dead_code)]
    pub async fn connected_count(&self) -> usize {
        self.agents.read().await.len()
    }
}
