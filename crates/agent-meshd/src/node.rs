use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_mesh_core::identity::{AgentKeypair, MessageId};
use agent_mesh_core::message::{
    AuthChallenge, AuthHello, AuthResponse, AuthResult, MeshEnvelope, MessageType,
};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair, NoiseTransport};
use anyhow::Result;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use futures_util::SinkExt;
use serde::Serialize;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message;

use crate::config::{MeshCredentials, NodeConfig};
use crate::proxy;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Peer Noise session state.
enum PeerNoise {
    /// Handshake in progress (waiting for msg3 from initiator).
    Handshaking(Box<NoiseHandshake>),
    /// Transport established.
    Established(NoiseTransport),
}

/// meshd daemon state machine.
///
/// Phase 1: `Started` → `Authenticated`
/// Phase 3 (future): → `Syncing` → `Connected`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NodeState {
    /// Local API running, no authentication token.
    Started,
    /// Token acquired, CP operations available.
    Authenticated,
}

pub struct MeshNode {
    keypair: AgentKeypair,
    noise_keypair: NoiseKeypair,
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
            keypair,
            noise_keypair,
            relay_url: config.relay_url,
            local_agent_url: config.local_agent_url,
            acl: Arc::new(RwLock::new(config.acl)),
            config_path,
            cp_url,
            state: Arc::new(RwLock::new(initial_state)),
            bearer_token: Arc::new(RwLock::new(creds.bearer_token)),
            mesh_dir,
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

    /// Start SIGHUP listener for ACL hot reload.
    pub fn start_acl_reload_listener(&self) {
        let Some(path) = self.config_path.clone() else {
            return;
        };
        let acl = Arc::clone(&self.acl);
        tokio::spawn(async move {
            let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                tracing::warn!("failed to register SIGHUP handler");
                return;
            };
            loop {
                sighup.recv().await;
                tracing::info!("SIGHUP received, reloading ACL from {path}");
                match NodeConfig::reload_acl(&path) {
                    Ok(new_acl) => {
                        let rule_count = new_acl.rules.len();
                        *acl.write().await = new_acl;
                        tracing::info!(rules = rule_count, "ACL reloaded");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ACL reload failed, keeping old policy");
                    }
                }
            }
        });
    }

    pub async fn run(&self) -> Result<()> {
        self.start_acl_reload_listener();
        loop {
            match self.connect_and_serve().await {
                Ok(()) => tracing::info!("relay connection closed, reconnecting..."),
                Err(e) => tracing::warn!(error = %e, "relay connection error, reconnecting..."),
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    async fn connect_and_serve(&self) -> Result<()> {
        let agent_id = self.keypair.agent_id();
        tracing::info!(relay = %self.relay_url, agent = agent_id.as_str(), "connecting to relay");

        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.relay_url).await?;
        let (mut sink, mut stream) = ws_stream.split();

        // Step 1: Send AuthHello.
        let hello = AuthHello {
            agent_id: agent_id.clone(),
        };
        sink.send(Message::text(serde_json::to_string(&hello)?))
            .await?;
        tracing::debug!("auth: hello sent");

        // Step 2: Receive AuthChallenge with nonce.
        let challenge: AuthChallenge = self
            .receive_json(&mut stream)
            .await
            .ok_or_else(|| anyhow::anyhow!("auth: no challenge received"))?;
        tracing::debug!("auth: challenge received");

        // Step 3: Sign the nonce and send AuthResponse.
        let sig = self.keypair.sign(challenge.nonce.as_bytes());
        let sig_b64 = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        };
        let response = AuthResponse {
            agent_id: agent_id.clone(),
            signature: sig_b64,
        };
        sink.send(Message::text(serde_json::to_string(&response)?))
            .await?;
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

        // Per-peer Noise sessions.
        let mut sessions: HashMap<String, PeerNoise> = HashMap::new();

        // Process incoming messages.
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&text, &mut sink, &mut sessions).await {
                        tracing::warn!(error = %e, "message handling error");
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
        sink: &mut SplitSink<WsStream, Message>,
        sessions: &mut HashMap<String, PeerNoise>,
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
                .handle_handshake(envelope, sink, sessions, &peer_key)
                .await;
        }

        // For encrypted messages, decrypt the payload.
        let payload = if envelope.encrypted {
            let transport = match sessions.get_mut(&peer_key) {
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
        let my_id = self.keypair.agent_id();
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
        )
        .await?;
        Ok(())
    }

    async fn handle_handshake(
        &self,
        envelope: MeshEnvelope,
        sink: &mut SplitSink<WsStream, Message>,
        sessions: &mut HashMap<String, PeerNoise>,
        peer_key: &str,
    ) -> Result<()> {
        let hs_data = envelope
            .payload
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("handshake payload not a string"))?;

        match sessions.get_mut(peer_key) {
            Some(PeerNoise::Handshaking(handshake)) => {
                // XX msg3: -> s, se (from initiator)
                handshake
                    .read_message(hs_data)
                    .map_err(|e| anyhow::anyhow!("noise read msg3: {e}"))?;

                if !handshake.is_finished() {
                    return Err(anyhow::anyhow!("handshake not finished after msg3"));
                }

                // Take ownership to transition state.
                let handshake = match sessions.remove(peer_key) {
                    Some(PeerNoise::Handshaking(h)) => *h,
                    _ => return Err(anyhow::anyhow!("unexpected peer state after msg3")),
                };
                let transport = handshake
                    .into_transport()
                    .map_err(|e| anyhow::anyhow!("noise transport: {e}"))?;
                sessions.insert(peer_key.to_string(), PeerNoise::Established(transport));
                tracing::info!(peer = peer_key, "noise handshake complete (responder)");
                Ok(())
            }
            Some(PeerNoise::Established(_)) | None => {
                // XX msg1: -> e (new handshake from initiator)
                // If there was an existing session, replace it.
                let mut handshake = NoiseHandshake::new_responder(&self.noise_keypair)
                    .map_err(|e| anyhow::anyhow!("noise responder init: {e}"))?;

                handshake
                    .read_message(hs_data)
                    .map_err(|e| anyhow::anyhow!("noise read msg1: {e}"))?;

                // XX msg2: <- e, ee, s, es
                let hs_reply = handshake
                    .write_message()
                    .map_err(|e| anyhow::anyhow!("noise write msg2: {e}"))?;

                let reply = MeshEnvelope::new_signed_reply(
                    &self.keypair,
                    envelope.from.clone(),
                    MessageType::Handshake,
                    Some(envelope.id),
                    serde_json::Value::String(hs_reply),
                )
                .map_err(|e| anyhow::anyhow!("envelope: {e}"))?;
                let json = serde_json::to_string(&reply)?;
                sink.send(Message::text(json)).await?;

                sessions.insert(
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
        sink: &mut SplitSink<WsStream, Message>,
        sessions: &mut HashMap<String, PeerNoise>,
        peer_key: &str,
        to: agent_mesh_core::identity::AgentId,
        msg_type: MessageType,
        in_reply_to: Option<MessageId>,
        payload: serde_json::Value,
        encrypt: bool,
    ) -> Result<()> {
        let response = if encrypt {
            let transport = match sessions.get_mut(peer_key) {
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
            MeshEnvelope::new_encrypted(
                &self.keypair,
                to,
                msg_type,
                in_reply_to,
                serde_json::Value::String(ciphertext),
            )
            .map_err(|e| anyhow::anyhow!("envelope: {e}"))?
        } else {
            MeshEnvelope::new_signed_reply(&self.keypair, to, msg_type, in_reply_to, payload)
                .map_err(|e| anyhow::anyhow!("envelope: {e}"))?
        };

        let json = serde_json::to_string(&response)?;
        sink.send(Message::text(json)).await?;
        Ok(())
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
        let keypair = cfg.keypair()?;
        let noise_keypair =
            NoiseKeypair::generate().map_err(|e| anyhow::anyhow!("noise keygen: {e}"))?;
        let config_path = cfg.config_path.clone();
        let creds = MeshCredentials::load(mesh_dir).unwrap_or_default();
        let cp_url = cfg.cp_url.clone().or_else(|| creds.cp_url.clone());
        let initial_state = if creds.bearer_token.is_some() {
            NodeState::Authenticated
        } else {
            NodeState::Started
        };
        Ok(MeshNode {
            keypair,
            noise_keypair,
            relay_url: cfg.relay_url,
            local_agent_url: cfg.local_agent_url,
            acl: Arc::new(RwLock::new(cfg.acl)),
            config_path,
            cp_url,
            state: Arc::new(RwLock::new(initial_state)),
            bearer_token: Arc::new(RwLock::new(creds.bearer_token)),
            mesh_dir: mesh_dir.to_path_buf(),
        })
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
