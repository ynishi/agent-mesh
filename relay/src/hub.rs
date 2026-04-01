use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::SplitSink;
use futures_util::SinkExt;
use mesh_proto::identity::AgentId;
use mesh_proto::message::{KeyRevocation, MeshEnvelope};
use rusqlite::Connection;
use tokio::sync::{Mutex, RwLock};

type WsSink = SplitSink<axum::extract::ws::WebSocket, axum::extract::ws::Message>;

/// Per-agent buffer limits.
const MAX_BUFFERED_PER_AGENT: usize = 100;
const BUFFER_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Heartbeat configuration.
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_THRESHOLD: Duration = Duration::from_secs(60);
const DEAD_THRESHOLD: Duration = Duration::from_secs(90);

/// Session token TTL for connection resumption.
const SESSION_TOKEN_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Stored session for connection resumption.
struct StoredSession {
    agent_id: String,
    created_at: Instant,
}

/// A buffered message waiting for delivery.
struct BufferedMessage {
    json: String,
    enqueued_at: Instant,
}

/// Token bucket for per-agent rate limiting.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,  // tokens per second
    burst: f64, // max tokens
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
            rate,
            burst,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
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
    /// Set of revoked agent IDs. Revoked agents cannot authenticate or receive messages.
    revoked: RwLock<HashSet<String>>,
    /// Session tokens for connection resumption: token → StoredSession.
    session_tokens: RwLock<HashMap<String, StoredSession>>,
    /// Per-agent rate limiters (token buckets).
    rate_limiters: Mutex<HashMap<String, TokenBucket>>,
    rate_limit: f64,
    rate_burst: f64,
    /// SQLite path for persistent state (revocations).
    db_path: Mutex<Option<PathBuf>>,
    /// Counters for metrics.
    pub messages_routed: AtomicU64,
    pub messages_buffered: AtomicU64,
    pub messages_dropped: AtomicU64,
    pub messages_rate_limited: AtomicU64,
    pub auth_successes: AtomicU64,
    pub auth_failures: AtomicU64,
}

/// Result of attempting to route a message.
pub enum RouteResult {
    /// Delivered to connected agent.
    Delivered,
    /// Target offline; message buffered for later delivery.
    Buffered,
    /// Target offline; buffer full, message dropped.
    BufferFull,
    /// Sender exceeded rate limit.
    RateLimited,
}

impl Hub {
    pub fn with_rate_limit(rate: f64, burst: f64) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            buffers: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            session_tokens: RwLock::new(HashMap::new()),
            rate_limiters: Mutex::new(HashMap::new()),
            rate_limit: rate,
            rate_burst: burst,
            db_path: Mutex::new(None),
            messages_routed: AtomicU64::new(0),
            messages_buffered: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            messages_rate_limited: AtomicU64::new(0),
            auth_successes: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
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
    /// Rejects routing if sender or target has been revoked.
    pub async fn route(&self, envelope: &MeshEnvelope) -> Result<RouteResult, String> {
        // Check revocation for both sender and target.
        {
            let revoked = self.revoked.read().await;
            if revoked.contains(envelope.from.as_str()) {
                return Err(format!("sender {} is revoked", envelope.from));
            }
            if revoked.contains(envelope.to.as_str()) {
                return Err(format!("target {} is revoked", envelope.to));
            }
        }

        // Rate limit check (per sender).
        {
            let sender_key = envelope.from.as_str().to_string();
            let mut limiters = self.rate_limiters.lock().await;
            let bucket = limiters
                .entry(sender_key)
                .or_insert_with(|| TokenBucket::new(self.rate_limit, self.rate_burst));
            if !bucket.try_consume() {
                self.messages_rate_limited.fetch_add(1, Ordering::Relaxed);
                return Ok(RouteResult::RateLimited);
            }
        }

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
                self.messages_routed.fetch_add(1, Ordering::Relaxed);
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
            self.messages_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(RouteResult::BufferFull);
        }

        queue.push_back(BufferedMessage {
            json,
            enqueued_at: now,
        });
        self.messages_buffered.fetch_add(1, Ordering::Relaxed);
        Ok(RouteResult::Buffered)
    }

    /// Check if an agent ID has been revoked.
    pub async fn is_revoked(&self, agent_id: &AgentId) -> bool {
        self.revoked.read().await.contains(agent_id.as_str())
    }

    /// Process a key revocation request.
    /// Verifies the signature, adds to revoked set, and disconnects the agent if online.
    pub async fn revoke(&self, revocation: &KeyRevocation) -> Result<(), String> {
        revocation
            .verify()
            .map_err(|e| format!("revocation signature invalid: {e}"))?;

        let id_str = revocation.agent_id.as_str().to_string();

        // Add to revoked set.
        {
            let mut revoked = self.revoked.write().await;
            if !revoked.insert(id_str.clone()) {
                return Ok(()); // Already revoked.
            }
        }

        // Disconnect the agent if currently connected.
        {
            let mut agents = self.agents.write().await;
            if agents.remove(&id_str).is_some() {
                tracing::info!(agent = id_str.as_str(), "revoked agent disconnected");
            }
        }

        // Drop any buffered messages for the revoked agent.
        {
            let mut buffers = self.buffers.write().await;
            buffers.remove(&id_str);
        }

        // Persist to SQLite.
        self.persist_revocation_async(&id_str, revocation.reason.as_deref())
            .await;

        tracing::warn!(
            agent = id_str.as_str(),
            reason = revocation.reason.as_deref().unwrap_or("none"),
            "agent key revoked"
        );
        Ok(())
    }

    /// Number of connected agents.
    pub async fn connected_count(&self) -> usize {
        self.agents.read().await.len()
    }

    /// Number of agents with buffered messages.
    pub async fn buffered_agent_count(&self) -> usize {
        self.buffers.read().await.len()
    }

    /// Number of revoked agents.
    pub async fn revoked_count(&self) -> usize {
        self.revoked.read().await.len()
    }

    /// List connected agent IDs.
    pub async fn connected_agent_ids(&self) -> Vec<String> {
        self.agents.read().await.keys().cloned().collect()
    }

    /// Issue a session token for an authenticated agent.
    /// Returns the token string to send in AuthResult.
    pub async fn issue_session_token(&self, agent_id: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self.session_tokens.write().await;
        tokens.insert(
            token.clone(),
            StoredSession {
                agent_id: agent_id.to_string(),
                created_at: Instant::now(),
            },
        );
        token
    }

    /// Validate a session token for resumption.
    /// Returns the agent_id if the token is valid and not expired.
    pub async fn validate_session_token(&self, token: &str) -> Option<String> {
        let tokens = self.session_tokens.read().await;
        let session = tokens.get(token)?;
        if Instant::now().duration_since(session.created_at) > SESSION_TOKEN_TTL {
            return None;
        }
        Some(session.agent_id.clone())
    }

    /// Initialize SQLite persistence: create table, load revoked set.
    pub async fn init_persistence(&self, db_path: &std::path::Path) -> Result<(), String> {
        let db_path_owned = db_path.to_path_buf();
        let ids = tokio::task::spawn_blocking(move || -> Result<Vec<String>, String> {
            let conn = Connection::open(&db_path_owned).map_err(|e| format!("open db: {e}"))?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS revoked_agents (
                    agent_id TEXT PRIMARY KEY,
                    reason TEXT,
                    revoked_at INTEGER NOT NULL
                )",
            )
            .map_err(|e| format!("create table: {e}"))?;

            let mut stmt = conn
                .prepare("SELECT agent_id FROM revoked_agents")
                .map_err(|e| format!("prepare: {e}"))?;
            let ids: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| format!("query: {e}"))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(ids)
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))??;

        let count = ids.len();
        {
            let mut revoked = self.revoked.write().await;
            for id in ids {
                revoked.insert(id);
            }
        }

        *self.db_path.lock().await = Some(db_path.to_path_buf());

        if count > 0 {
            tracing::info!(count, "loaded persisted revocations");
        }
        Ok(())
    }

    /// Persist a revocation to SQLite (async).
    async fn persist_revocation_async(&self, agent_id: &str, reason: Option<&str>) {
        let db_path = {
            let path = self.db_path.lock().await;
            match path.as_ref() {
                Some(p) => p.clone(),
                None => return,
            }
        };
        let agent_id = agent_id.to_string();
        let reason = reason.map(|s| s.to_string());
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR IGNORE INTO revoked_agents (agent_id, reason, revoked_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![agent_id, reason, now],
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .await
        {
            tracing::warn!(error = %e, "failed to persist revocation");
        }
    }

    /// Graceful shutdown: send WS Close to all connected agents.
    pub async fn shutdown(&self) {
        let agents = self.agents.write().await;
        let count = agents.len();
        for (id, session) in agents.iter() {
            let mut sink = session.sink.lock().await;
            if sink
                .send(axum::extract::ws::Message::Close(None))
                .await
                .is_err()
            {
                tracing::debug!(agent = id.as_str(), "close frame send failed");
            }
        }
        if count > 0 {
            tracing::info!(count, "sent close frames to all agents");
        }
    }

    /// Check rate limit for a given agent. Returns true if allowed.
    /// Exposed for testing.
    #[cfg(test)]
    async fn check_rate_limit(&self, agent_id: &str) -> bool {
        let mut limiters = self.rate_limiters.lock().await;
        let bucket = limiters
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.rate_limit, self.rate_burst));
        bucket.try_consume()
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
                    tracing::warn!(
                        agent = id.as_str(),
                        "dead agent removed (heartbeat timeout)"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst() {
        let mut bucket = TokenBucket::new(10.0, 5.0);
        for _ in 0..5 {
            assert!(bucket.try_consume());
        }
        // 6th should fail (burst exhausted)
        assert!(!bucket.try_consume());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(100.0, 5.0);
        // Exhaust burst
        for _ in 0..5 {
            bucket.try_consume();
        }
        assert!(!bucket.try_consume());

        // Simulate time passing by backdating last_refill
        bucket.last_refill = Instant::now() - Duration::from_millis(100);
        // 100ms at 100 tokens/sec = 10 tokens refilled (capped at burst=5)
        assert!(bucket.try_consume());
    }

    #[tokio::test]
    async fn session_token_issue_and_validate() {
        let hub = Hub::with_rate_limit(10.0, 5.0);
        let token = hub.issue_session_token("agent-1").await;

        let result = hub.validate_session_token(&token).await;
        assert_eq!(result, Some("agent-1".to_string()));
    }

    #[tokio::test]
    async fn session_token_invalid() {
        let hub = Hub::with_rate_limit(10.0, 5.0);
        let result = hub.validate_session_token("bogus-token").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revocation_blocks_agent() {
        let hub = Hub::with_rate_limit(10.0, 5.0);
        let agent_id = AgentId::from_raw("revoked-agent".to_string());

        assert!(!hub.is_revoked(&agent_id).await);

        // Manually insert into revoked set (bypassing signature verification)
        hub.revoked
            .write()
            .await
            .insert("revoked-agent".to_string());

        assert!(hub.is_revoked(&agent_id).await);
        assert_eq!(hub.revoked_count().await, 1);
    }

    #[tokio::test]
    async fn connected_count_starts_at_zero() {
        let hub = Hub::with_rate_limit(10.0, 5.0);
        assert_eq!(hub.connected_count().await, 0);
        assert_eq!(hub.buffered_agent_count().await, 0);
        assert_eq!(hub.revoked_count().await, 0);
    }

    #[tokio::test]
    async fn rate_limit_enforced() {
        let hub = Hub::with_rate_limit(10.0, 3.0); // burst=3
        for _ in 0..3 {
            assert!(hub.check_rate_limit("agent-1").await);
        }
        assert!(!hub.check_rate_limit("agent-1").await);

        // Different agent has its own bucket
        assert!(hub.check_rate_limit("agent-2").await);
    }

    #[tokio::test]
    async fn metrics_start_at_zero() {
        let hub = Hub::with_rate_limit(10.0, 5.0);
        assert_eq!(hub.messages_routed.load(Ordering::Relaxed), 0);
        assert_eq!(hub.messages_buffered.load(Ordering::Relaxed), 0);
        assert_eq!(hub.messages_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(hub.messages_rate_limited.load(Ordering::Relaxed), 0);
        assert_eq!(hub.auth_successes.load(Ordering::Relaxed), 0);
        assert_eq!(hub.auth_failures.load(Ordering::Relaxed), 0);
    }
}
