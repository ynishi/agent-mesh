use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::SplitSink;
use futures_util::SinkExt;
use mesh_proto::identity::AgentId;
use mesh_proto::message::MeshEnvelope;
use tokio::sync::{Mutex, RwLock};

type WsSink = SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>;

/// Per-agent buffer limits.
const MAX_BUFFERED_PER_AGENT: usize = 100;
const BUFFER_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Heartbeat configuration.
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_THRESHOLD: Duration = Duration::from_secs(60);
const DEAD_THRESHOLD: Duration = Duration::from_secs(90);

/// A buffered message waiting for delivery.
struct BufferedMessage {
    json: String,
    enqueued_at: Instant,
}

/// Connected agent session.
struct AgentSession {
    sink: Mutex<WsSink>,
    last_activity: Mutex<Instant>,
}

/// Central hub that routes messages between connected agents.
/// Buffers messages for offline agents (up to limits).
/// Runs a background reaper to detect and remove dead agents.
pub struct Hub {
    agents: RwLock<HashMap<String, Arc<AgentSession>>>,
    buffers: RwLock<HashMap<String, VecDeque<BufferedMessage>>>,
}

/// Result of attempting to route a message.
pub enum RouteResult {
    /// Delivered to connected agent.
    Delivered,
    /// Target offline; message buffered for later delivery.
    Buffered,
    /// Target offline; buffer full, message dropped.
    BufferFull,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            buffers: RwLock::new(HashMap::new()),
        }
    }

    /// Start the background reaper task for dead agent detection.
    /// Call once after creating the Hub.
    pub fn start_reaper(self: &Arc<Self>) {
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PING_INTERVAL).await;
                hub.reap_dead_agents().await;
            }
        });
    }

    /// Register a connected agent's WebSocket sink.
    /// Flushes any buffered messages to the newly connected agent.
    pub async fn register(&self, agent_id: &AgentId, sink: WsSink) {
        let session = Arc::new(AgentSession {
            sink: Mutex::new(sink),
            last_activity: Mutex::new(Instant::now()),
        });
        let id_str = agent_id.as_str().to_string();

        {
            let mut agents = self.agents.write().await;
            agents.insert(id_str.clone(), session.clone());
        }
        tracing::info!(agent = agent_id.as_str(), "agent registered");

        // Flush buffered messages.
        let pending = {
            let mut buffers = self.buffers.write().await;
            buffers.remove(&id_str)
        };
        if let Some(messages) = pending {
            let now = Instant::now();
            let mut sink = session.sink.lock().await;
            let mut delivered = 0usize;
            let mut expired = 0usize;
            for msg in messages {
                if now.duration_since(msg.enqueued_at) > BUFFER_TTL {
                    expired += 1;
                    continue;
                }
                if sink
                    .send(axum::extract::ws::Message::text(msg.json))
                    .await
                    .is_ok()
                {
                    delivered += 1;
                } else {
                    break;
                }
            }
            if delivered > 0 || expired > 0 {
                tracing::info!(
                    agent = agent_id.as_str(),
                    delivered,
                    expired,
                    "flushed buffered messages"
                );
            }
        }
    }

    /// Remove a disconnected agent.
    pub async fn unregister(&self, agent_id: &AgentId) {
        let mut agents = self.agents.write().await;
        agents.remove(agent_id.as_str());
        tracing::info!(agent = agent_id.as_str(), "agent unregistered");
    }

    /// Update last activity timestamp for an agent.
    /// Called on every received message.
    pub async fn touch(&self, agent_id: &AgentId) {
        let agents = self.agents.read().await;
        if let Some(session) = agents.get(agent_id.as_str()) {
            *session.last_activity.lock().await = Instant::now();
        }
    }

    /// Route an envelope to the destination agent.
    /// If the target is offline, buffers the message for later delivery.
    pub async fn route(&self, envelope: &MeshEnvelope) -> Result<RouteResult, String> {
        let json = serde_json::to_string(envelope).map_err(|e| format!("serialize: {e}"))?;
        let target_key = envelope.to.as_str().to_string();

        // Try direct delivery first.
        {
            let agents = self.agents.read().await;
            if let Some(session) = agents.get(&target_key) {
                let mut sink = session.sink.lock().await;
                sink.send(axum::extract::ws::Message::text(json))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                return Ok(RouteResult::Delivered);
            }
        }

        // Target offline — buffer the message.
        let mut buffers = self.buffers.write().await;
        let queue = buffers.entry(target_key).or_default();

        // Evict expired messages first.
        let now = Instant::now();
        while let Some(front) = queue.front() {
            if now.duration_since(front.enqueued_at) > BUFFER_TTL {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= MAX_BUFFERED_PER_AGENT {
            return Ok(RouteResult::BufferFull);
        }

        queue.push_back(BufferedMessage {
            json,
            enqueued_at: now,
        });
        Ok(RouteResult::Buffered)
    }

    /// Number of connected agents.
    #[allow(dead_code)]
    pub async fn connected_count(&self) -> usize {
        self.agents.read().await.len()
    }

    /// Number of agents with buffered messages.
    #[allow(dead_code)]
    pub async fn buffered_agent_count(&self) -> usize {
        self.buffers.read().await.len()
    }

    /// Background reaper: sends Ping to idle agents, removes dead ones.
    async fn reap_dead_agents(&self) {
        let now = Instant::now();
        let mut to_ping = Vec::new();
        let mut to_remove = Vec::new();

        // Collect agents that need action.
        {
            let agents = self.agents.read().await;
            for (id, session) in agents.iter() {
                let last = *session.last_activity.lock().await;
                let idle = now.duration_since(last);

                if idle > DEAD_THRESHOLD {
                    to_remove.push(id.clone());
                } else if idle > PING_THRESHOLD {
                    to_ping.push((id.clone(), Arc::clone(session)));
                }
            }
        }

        // Send Ping to idle agents.
        for (id, session) in &to_ping {
            let mut sink = session.sink.lock().await;
            if sink
                .send(axum::extract::ws::Message::Ping(Vec::new().into()))
                .await
                .is_err()
            {
                // Send failed — mark for removal.
                to_remove.push(id.clone());
            } else {
                tracing::debug!(agent = id.as_str(), "sent heartbeat ping");
            }
        }

        // Remove dead agents.
        if !to_remove.is_empty() {
            let mut agents = self.agents.write().await;
            for id in &to_remove {
                if agents.remove(id.as_str()).is_some() {
                    tracing::warn!(agent = id.as_str(), "dead agent removed (heartbeat timeout)");
                }
            }
        }
    }
}
