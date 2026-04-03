use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_mesh_core::agent_card::AgentCard;
use agent_mesh_core::identity::{AgentKeypair, MessageId};
use agent_mesh_core::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use anyhow::Result;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use futures_util::SinkExt;
use serde::Serialize;
use tokio::sync::{oneshot, Mutex, Notify, RwLock};
use tokio_tungstenite::tungstenite::Message;

use crate::config::{MeshCredentials, NodeConfig};
use crate::cp_sync;
use crate::local_api::{self, LocalApiState};
use crate::proxy;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) type WsSink = SplitSink<WsStream, Message>;
pub(crate) type SharedSink = Arc<Mutex<Option<WsSink>>>;
pub(crate) type SharedSessions = Arc<Mutex<HashMap<String, PeerNoise>>>;
pub(crate) type SharedPending = Arc<Mutex<HashMap<MessageId, oneshot::Sender<MeshEnvelope>>>>;

/// Peer Noise session state.
pub(crate) enum PeerNoise {
    /// Handshake in progress (waiting for msg3 from initiator).
    Handshaking(Box<NoiseHandshake>),
    /// Transport established.
    Established(NoiseTransport),
}

/// meshd daemon state machine.
///
/// `Started` → `Authenticated` → `Syncing` → `Connected`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NodeState {
    /// Local API running, no authentication token.
    Started,
    /// Token acquired, CP operations available.
    Authenticated,
    /// CP Sync WebSocket connected; waiting for relay connection.
    Syncing,
    /// Both CP Sync and relay connections are active.
    Connected,
}

pub struct MeshNode {
    /// Current active keypair, wrapped for hot-reload support.
    keypair: Arc<RwLock<AgentKeypair>>,
    /// Pending new keypair during a rotation (applied on /rotate/complete).
    pending_keypair: Arc<RwLock<Option<AgentKeypair>>>,
    /// Notify to force immediate relay reconnect (e.g., after key rotation).
    relay_cancel: Arc<Notify>,
    noise_keypair: Arc<NoiseKeypair>,
    relay_url: String,
    local_agent_url: String,
    acl: Arc<RwLock<agent_mesh_core::acl::AclPolicy>>,
    config_path: Option<String>,
    /// Control Plane URL.
    cp_url: Option<String>,
    /// Current daemon state.
    state: Arc<RwLock<NodeState>>,
    /// Bearer token for CP authentication.
    bearer_token: Arc<RwLock<Option<String>>>,
    /// Directory used for credential storage (typically `~/.mesh/`).
    mesh_dir: PathBuf,
    /// Peer agent cards received from CP Sync.
    peers: Arc<RwLock<Vec<AgentCard>>>,
    /// Revoked key agent IDs received from CP Sync.
    revoked_keys: Arc<RwLock<HashSet<String>>>,
    /// Shared relay sink — None when relay is not connected.
    shared_sink: SharedSink,
    /// Shared Noise sessions per peer.
    shared_sessions: SharedSessions,
    /// Pending in-flight request map (message_id → oneshot sender).
    shared_pending: SharedPending,
}

impl MeshNode {
    pub fn new(config: NodeConfig) -> Result<Self> {
        let keypair = config.keypair()?;
        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| anyhow::anyhow!("noise keygen: {e}"))?;
        let config_path = config.config_path.clone();

        let mesh_dir = MeshCredentials::default_mesh_dir()?;
        let creds = MeshCredentials::load(&mesh_dir).unwrap_or_default();

        // Merge: cp_url from CLI/config takes precedence over stored credentials.
        let cp_url = config.cp_url.clone().or_else(|| creds.cp_url.clone());

        let initial_state = if creds.bearer_token.is_some() {
            NodeState::Authenticated
        } else {
            NodeState::Started
        };

        Ok(Self {
            keypair: Arc::new(RwLock::new(keypair)),
            pending_keypair: Arc::new(RwLock::new(None)),
            relay_cancel: Arc::new(Notify::new()),
            noise_keypair: Arc::new(noise_keypair),
            relay_url: config.relay_url,
            local_agent_url: config.local_agent_url,
            acl: Arc::new(RwLock::new(config.acl)),
            config_path,
            cp_url,
            state: Arc::new(RwLock::new(initial_state)),
            bearer_token: Arc::new(RwLock::new(creds.bearer_token)),
            mesh_dir,
            peers: Arc::new(RwLock::new(Vec::new())),
            revoked_keys: Arc::new(RwLock::new(HashSet::new())),
            shared_sink: Arc::new(Mutex::new(None)),
            shared_sessions: Arc::new(Mutex::new(HashMap::new())),
            shared_pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    // ── Accessors used by Subtask 2 (local_api.rs) ──────────────────────────

    /// Returns a shared reference to the daemon state.
    pub fn state(&self) -> Arc<RwLock<NodeState>> {
        Arc::clone(&self.state)
    }

    /// Returns a shared reference to the bearer token.
    pub fn bearer_token(&self) -> Arc<RwLock<Option<String>>> {
        Arc::clone(&self.bearer_token)
    }

    /// Returns the Control Plane URL, if configured.
    pub fn cp_url(&self) -> Option<&str> {
        self.cp_url.as_deref()
    }

    /// Returns the mesh credentials directory (typically `~/.mesh/`).
    pub fn mesh_dir(&self) -> &Path {
        &self.mesh_dir
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    pub async fn run(&self) -> Result<()> {
        tokio::select! {
            r = self.local_api_server() => {
                tracing::error!(error = ?r, "local API server exited");
                r
            }
            r = self.relay_loop() => {
                tracing::error!(error = ?r, "relay loop exited");
                r
            }
            r = self.cp_sync_loop_wrapper() => {
                tracing::error!(error = ?r, "CP sync loop exited");
                r
            }
        }
    }

    /// Wraps `cp_sync::cp_sync_loop`. If `cp_url` is not configured, waits
    /// indefinitely so the other tasks can still operate.
    async fn cp_sync_loop_wrapper(&self) -> Result<()> {
        let Some(ref cp_url) = self.cp_url else {
            tracing::info!("cp_url not configured, skipping CP sync");
            std::future::pending::<()>().await;
            return Ok(());
        };
        let agent_id = self.keypair.read().await.agent_id();
        cp_sync::cp_sync_loop(
            cp_url,
            Arc::clone(&self.bearer_token),
            &agent_id,
            Arc::clone(&self.acl),
            Arc::clone(&self.peers),
            Arc::clone(&self.revoked_keys),
            Arc::clone(&self.state),
        )
        .await
    }

    /// Relay reconnect loop. If `relay_url` is empty, waits indefinitely so the
    /// Local API can still operate (Local-API-only mode).
    async fn relay_loop(&self) -> Result<()> {
        if self.relay_url.is_empty() {
            tracing::info!("relay_url not configured, skipping relay connection");
            std::future::pending::<()>().await;
            return Ok(());
        }
        loop {
            // Syncing → Connected on relay connection establishment.
            {
                let mut s = self.state.write().await;
                if *s == NodeState::Syncing {
                    *s = NodeState::Connected;
                    tracing::info!("relay connected, state → Connected");
                }
            }

            match self.connect_and_serve().await {
                Ok(()) => tracing::info!("relay connection closed, reconnecting..."),
                Err(e) => tracing::warn!(error = %e, "relay connection error, reconnecting..."),
            }

            // Connected → Syncing on relay disconnect (if CP sync is still up).
            {
                let mut s = self.state.write().await;
                if *s == NodeState::Connected {
                    *s = NodeState::Syncing;
                    tracing::info!("relay disconnected, state → Syncing");
                }
            }

            // Wait 3s before reconnect, but allow relay_cancel to skip the wait immediately.
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                _ = self.relay_cancel.notified() => {
                    tracing::info!("relay reconnect triggered by key rotation");
                }
            }
        }
    }

    /// Bind the UDS Local API socket and serve.
    async fn local_api_server(&self) -> Result<()> {
        let sock_path = self.mesh_dir.join("meshd.sock");

        // Remove stale socket from previous run (ignore ENOENT).
        let _ = std::fs::remove_file(&sock_path);

        let listener = tokio::net::UnixListener::bind(&sock_path)
            .map_err(|e| anyhow::anyhow!("failed to bind UDS {}: {e}", sock_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| anyhow::anyhow!("failed to set permissions on {}: {e}", sock_path.display()),
            )?;
        }

        let state = LocalApiState {
            cp_url: Arc::new(tokio::sync::RwLock::new(self.cp_url.clone())),
            bearer_token: Arc::clone(&self.bearer_token),
            node_state: Arc::clone(&self.state),
            http_client: reqwest::Client::new(),
            mesh_dir: self.mesh_dir.clone(),
            peers: Arc::clone(&self.peers),
            revoked_keys: Arc::clone(&self.revoked_keys),
            keypair: Arc::clone(&self.keypair),
            pending_keypair: Arc::clone(&self.pending_keypair),
            relay_cancel: Arc::clone(&self.relay_cancel),
            config_path: self.config_path.clone(),
            shared_sink: Arc::clone(&self.shared_sink),
            shared_sessions: Arc::clone(&self.shared_sessions),
            shared_pending: Arc::clone(&self.shared_pending),
            noise_keypair: Arc::clone(&self.noise_keypair),
        };

        let router = local_api::router(state);
        tracing::info!(path = %sock_path.display(), "local API listening on UDS");

        axum::serve(listener, router.into_make_service())
            .await
            .map_err(|e| anyhow::anyhow!("local API server error: {e}"))
    }

    async fn connect_and_serve(&self) -> Result<()> {
        // Clone keypair at connection start to avoid holding the RwLock for the
        // entire connection lifetime (long-lived async function).
        let keypair = self.keypair.read().await.clone();
        let agent_id = keypair.agent_id();
        tracing::info!(relay = %self.relay_url, agent = agent_id.as_str(), "connecting to relay");

        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.relay_url).await?;
        let (sink, mut stream) = ws_stream.split();

        // Step 1: Send AuthHello.
        let hello = AuthHello {
            agent_id: agent_id.clone(),
        };
        {
            let mut guard = self.shared_sink.lock().await;
            *guard = Some(sink);
            guard
                .as_mut()
                .expect("just set to Some")
                .send(Message::text(serde_json::to_string(&hello)?))
                .await?;
        }
        tracing::debug!("auth: hello sent");

        // Step 2: Receive AuthChallenge with nonce.
        let challenge: AuthChallenge = self
            .receive_json(&mut stream)
            .await
            .ok_or_else(|| anyhow::anyhow!("auth: no challenge received"))?;
        tracing::debug!("auth: challenge received");

        // Step 3: Sign the nonce and send AuthResponse.
        let sig = keypair.sign(challenge.nonce.as_bytes());
        let sig_b64 = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        };
        let response = AuthResponse {
            agent_id: agent_id.clone(),
            signature: sig_b64,
        };
        {
            let mut guard = self.shared_sink.lock().await;
            guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("sink unexpectedly None during auth"))?
                .send(Message::text(serde_json::to_string(&response)?))
                .await?;
        }
        tracing::debug!("auth: response sent");

        // Step 4: Receive AuthResult.
        let result: AuthResult = self
            .receive_json(&mut stream)
            .await
            .ok_or_else(|| anyhow::anyhow!("auth: no result received"))?;
        if !result.success {
            return Err(anyhow::anyhow!(
                "auth failed: {}",
                result.error.unwrap_or_default()
            ));
        }
        tracing::info!("auth: challenge-response verified");

        // Clear any stale sessions from a previous connection.
        self.shared_sessions.lock().await.clear();

        // Process incoming messages.
        let result = self.reader_loop(&mut stream, &keypair).await;

        // Cleanup on disconnect (normal or error).
        self.cleanup_relay_state().await;

        result
    }

    async fn reader_loop(
        &self,
        stream: &mut SplitStream<WsStream>,
        keypair: &AgentKeypair,
    ) -> Result<()> {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let envelope: MeshEnvelope = match serde_json::from_str(&text) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to parse envelope");
                            continue;
                        }
                    };

                    if let Some(reply_to) = envelope.in_reply_to {
                        // Response message — route to pending map.
                        let mut pending = self.shared_pending.lock().await;
                        if let Some(tx) = pending.remove(&reply_to) {
                            let _ = tx.send(envelope);
                        }
                    } else {
                        // Request message — delegate to handle_message.
                        let raw = text;
                        if let Err(e) = self
                            .handle_message(&raw, &self.shared_sink, &self.shared_sessions, keypair)
                            .await
                        {
                            tracing::warn!(error = %e, "message handling error");
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    tracing::info!("relay closed connection");
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Called on relay disconnect (normal or error). Resets shared relay state
    /// and drains pending oneshotsso waiting callers receive RecvError.
    async fn cleanup_relay_state(&self) {
        *self.shared_sink.lock().await = None;
        self.shared_sessions.lock().await.clear();
        // Drain pending: dropping Senders causes RecvError on the receiver side.
        self.shared_pending.lock().await.clear();
    }

    async fn receive_json<T: serde::de::DeserializeOwned>(
        &self,
        stream: &mut SplitStream<WsStream>,
    ) -> Option<T> {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => serde_json::from_str(&text).ok(),
            _ => None,
        }
    }

    async fn handle_message(
        &self,
        text: &str,
        sink: &SharedSink,
        sessions: &SharedSessions,
        keypair: &AgentKeypair,
    ) -> Result<()> {
        let envelope: MeshEnvelope = serde_json::from_str(text)?;

        // Verify signature.
        envelope
            .verify()
            .map_err(|e| anyhow::anyhow!("sig verify: {e}"))?;

        let peer_key = envelope.from.as_str().to_string();

        // Handle Noise handshake messages.
        if envelope.msg_type == MessageType::Handshake {
            return self
                .handle_handshake(envelope, sink, sessions, &peer_key, keypair)
                .await;
        }

        // For encrypted messages, decrypt the payload.
        let payload = if envelope.encrypted {
            let mut guard = sessions.lock().await;
            let transport = match guard.get_mut(&peer_key) {
                Some(PeerNoise::Established(t)) => t,
                _ => {
                    return Err(anyhow::anyhow!(
                        "encrypted message from {} but no noise session",
                        peer_key
                    ));
                }
            };
            let ciphertext = envelope
                .payload
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("encrypted payload not a string"))?;
            let plaintext = transport
                .decrypt(ciphertext)
                .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            serde_json::from_slice(&plaintext)?
        } else {
            envelope.payload.clone()
        };

        // Check ACL.
        let capability = payload
            .get("capability")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let my_id = keypair.agent_id();
        if !self
            .acl
            .read()
            .await
            .is_allowed(&envelope.from, &my_id, capability)
        {
            tracing::warn!(
                from = envelope.from.as_str(),
                capability = capability,
                "ACL denied"
            );
            let err_payload = serde_json::json!({"error": "acl_denied", "capability": capability});
            self.send_response(
                sink,
                sessions,
                &peer_key,
                envelope.from.clone(),
                MessageType::Error,
                Some(envelope.id),
                err_payload,
                envelope.encrypted,
                keypair,
            )
            .await?;
            return Ok(());
        }

        // Proxy to local agent.
        let response_payload = proxy::forward_to_local(&self.local_agent_url, &payload).await?;

        // Send response back through relay.
        self.send_response(
            sink,
            sessions,
            &peer_key,
            envelope.from,
            MessageType::Response,
            Some(envelope.id),
            response_payload,
            envelope.encrypted,
            keypair,
        )
        .await?;
        Ok(())
    }

    async fn handle_handshake(
        &self,
        envelope: MeshEnvelope,
        sink: &SharedSink,
        sessions: &SharedSessions,
        peer_key: &str,
        keypair: &AgentKeypair,
    ) -> Result<()> {
        let hs_data = envelope
            .payload
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("handshake payload not a string"))?
            .to_string();

        // Lock sessions for the entire handshake state machine to avoid
        // partial-update issues (get_mut → remove → insert pattern).
        let mut guard = sessions.lock().await;

        match guard.get_mut(peer_key) {
            Some(PeerNoise::Handshaking(handshake)) => {
                // XX msg3: -> s, se (from initiator)
                handshake
                    .read_message(&hs_data)
                    .map_err(|e| anyhow::anyhow!("noise read msg3: {e}"))?;

                if !handshake.is_finished() {
                    return Err(anyhow::anyhow!("handshake not finished after msg3"));
                }

                // Take ownership to transition state.
                let handshake = match guard.remove(peer_key) {
                    Some(PeerNoise::Handshaking(h)) => *h,
                    _ => return Err(anyhow::anyhow!("unexpected peer state after msg3")),
                };
                let transport = handshake
                    .into_transport()
                    .map_err(|e| anyhow::anyhow!("noise transport: {e}"))?;
                guard.insert(peer_key.to_string(), PeerNoise::Established(transport));
                tracing::info!(peer = peer_key, "noise handshake complete (responder)");
                Ok(())
            }
            Some(PeerNoise::Established(_)) | None => {
                // XX msg1: -> e (new handshake from initiator)
                // If there was an existing session, replace it.
                let mut handshake = NoiseHandshake::new_responder(&self.noise_keypair)
                    .map_err(|e| anyhow::anyhow!("noise responder init: {e}"))?;

                handshake
                    .read_message(&hs_data)
                    .map_err(|e| anyhow::anyhow!("noise read msg1: {e}"))?;

                // XX msg2: <- e, ee, s, es
                let hs_reply = handshake
                    .write_message()
                    .map_err(|e| anyhow::anyhow!("noise write msg2: {e}"))?;

                let reply = MeshEnvelope::new_signed_reply(
                    keypair,
                    envelope.from.clone(),
                    MessageType::Handshake,
                    Some(envelope.id),
                    serde_json::Value::String(hs_reply),
                )
                .map_err(|e| anyhow::anyhow!("envelope: {e}"))?;
                let json = serde_json::to_string(&reply)?;

                // Release the sessions lock before acquiring sink lock to
                // maintain the lock order: sink → sessions → pending.
                drop(guard);

                sink.lock()
                    .await
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("sink not connected during handshake"))?
                    .send(Message::text(json))
                    .await?;

                // Re-acquire sessions lock to insert the new handshake state.
                sessions.lock().await.insert(
                    peer_key.to_string(),
                    PeerNoise::Handshaking(Box::new(handshake)),
                );

                tracing::debug!(
                    peer = peer_key,
                    "noise handshake: msg2 sent, waiting for msg3"
                );
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_response(
        &self,
        sink: &SharedSink,
        sessions: &SharedSessions,
        peer_key: &str,
        to: agent_mesh_core::identity::AgentId,
        msg_type: MessageType,
        in_reply_to: Option<MessageId>,
        payload: serde_json::Value,
        encrypt: bool,
        keypair: &AgentKeypair,
    ) -> Result<()> {
        let response = if encrypt {
            let mut guard = sessions.lock().await;
            let transport = match guard.get_mut(peer_key) {
                Some(PeerNoise::Established(t)) => t,
                _ => {
                    return Err(anyhow::anyhow!(
                        "cannot encrypt response: no noise session for {}",
                        peer_key
                    ));
                }
            };
            let plaintext = serde_json::to_vec(&payload)?;
            let ciphertext = transport
                .encrypt(&plaintext)
                .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
            // Release sessions lock before building envelope (no longer needed).
            drop(guard);
            MeshEnvelope::new_encrypted(
                keypair,
                to,
                msg_type,
                in_reply_to,
                serde_json::Value::String(ciphertext),
            )
            .map_err(|e| anyhow::anyhow!("envelope: {e}"))?
        } else {
            MeshEnvelope::new_signed_reply(keypair, to, msg_type, in_reply_to, payload)
                .map_err(|e| anyhow::anyhow!("envelope: {e}"))?
        };

        let json = serde_json::to_string(&response)?;
        sink.lock()
            .await
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("sink not connected"))?
            .send(Message::text(json))
            .await?;
        Ok(())
    }

    /// Creates a `MeshNode` with a caller-supplied mesh directory, bypassing `$HOME/.mesh/` lookup.
    ///
    /// Unlike [`MeshNode::new`], this method does not read from the default mesh directory.
    /// Intended for integration tests and custom deployments.
    pub fn new_with_mesh_dir(config: NodeConfig, mesh_dir: &Path) -> Result<Self> {
        let keypair = config.keypair()?;
        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| anyhow::anyhow!("noise keygen: {e}"))?;
        let config_path = config.config_path.clone();
        let creds = MeshCredentials::load(mesh_dir).unwrap_or_default();
        let cp_url = config.cp_url.clone().or_else(|| creds.cp_url.clone());
        let bearer_token = creds.bearer_token.or(config.bearer_token);
        let initial_state = if bearer_token.is_some() {
            NodeState::Authenticated
        } else {
            NodeState::Started
        };
        Ok(MeshNode {
            keypair: Arc::new(RwLock::new(keypair)),
            pending_keypair: Arc::new(RwLock::new(None)),
            relay_cancel: Arc::new(Notify::new()),
            noise_keypair: Arc::new(noise_keypair),
            relay_url: config.relay_url,
            local_agent_url: config.local_agent_url,
            acl: Arc::new(RwLock::new(config.acl)),
            config_path,
            cp_url,
            state: Arc::new(RwLock::new(initial_state)),
            bearer_token: Arc::new(RwLock::new(bearer_token)),
            mesh_dir: mesh_dir.to_path_buf(),
            peers: Arc::new(RwLock::new(Vec::new())),
            revoked_keys: Arc::new(RwLock::new(HashSet::new())),
            shared_sink: Arc::new(Mutex::new(None)),
            shared_sessions: Arc::new(Mutex::new(HashMap::new())),
            shared_pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::identity::AgentKeypair;

    /// Creates a unique temp directory for each test (no external deps).
    fn temp_mesh_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("meshd-node-test-{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_config(secret: &str, cp_url: Option<&str>) -> NodeConfig {
        NodeConfig {
            secret_key_hex: secret.to_string(),
            relay_url: String::new(),
            local_agent_url: String::new(),
            acl: agent_mesh_core::acl::AclPolicy::default(),
            config_path: None,
            cp_url: cp_url.map(str::to_string),
            bearer_token: None,
        }
    }

    /// Creates a MeshNode with a caller-supplied mesh_dir, bypassing HOME lookup.
    fn node_with_mesh_dir(cfg: NodeConfig, mesh_dir: &Path) -> Result<MeshNode> {
        MeshNode::new_with_mesh_dir(cfg, mesh_dir)
    }

    #[tokio::test]
    async fn initial_state_without_token_is_started() {
        let kp = AgentKeypair::generate();
        let dir = temp_mesh_dir("no-token");
        let cfg = make_config(&hex::encode(kp.secret_bytes()), None);
        let node = node_with_mesh_dir(cfg, &dir).unwrap();

        let state = node.state().read().await.clone();
        assert_eq!(state, NodeState::Started);
        assert!(node.bearer_token().read().await.is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn initial_state_with_token_is_authenticated() {
        let kp = AgentKeypair::generate();
        let dir = temp_mesh_dir("with-token");

        let creds = MeshCredentials {
            bearer_token: Some("tok-xyz".into()),
            cp_url: None,
        };
        creds.save(&dir).unwrap();

        let cfg = make_config(&hex::encode(kp.secret_bytes()), None);
        let node = node_with_mesh_dir(cfg, &dir).unwrap();

        let state = node.state().read().await.clone();
        assert_eq!(state, NodeState::Authenticated);
        assert_eq!(node.bearer_token().read().await.as_deref(), Some("tok-xyz"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn cp_url_from_config_is_accessible() {
        let kp = AgentKeypair::generate();
        let dir = temp_mesh_dir("cp-url");
        let cfg = make_config(
            &hex::encode(kp.secret_bytes()),
            Some("http://cp.example.com"),
        );
        let node = node_with_mesh_dir(cfg, &dir).unwrap();

        assert_eq!(node.cp_url(), Some("http://cp.example.com"));
        assert_eq!(node.mesh_dir(), dir.as_path());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
