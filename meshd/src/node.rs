use anyhow::Result;
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use mesh_proto::identity::AgentKeypair;
use mesh_proto::message::{AuthHandshake, MeshEnvelope, MessageType};
use tokio_tungstenite::tungstenite::Message;

use crate::config::NodeConfig;
use crate::proxy;

pub struct MeshNode {
    keypair: AgentKeypair,
    relay_url: String,
    local_agent_url: String,
    acl: mesh_proto::acl::AclPolicy,
}

impl MeshNode {
    pub fn new(config: NodeConfig) -> Result<Self> {
        let keypair = config.keypair()?;
        Ok(Self {
            keypair,
            relay_url: config.relay_url,
            local_agent_url: config.local_agent_url,
            acl: config.acl,
        })
    }

    pub async fn run(&self) -> Result<()> {
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

        // Send auth handshake.
        let handshake = AuthHandshake {
            agent_id: agent_id.clone(),
            signature: String::new(), // v0.1: no challenge
            nonce: String::new(),
        };
        let handshake_json = serde_json::to_string(&handshake)?;
        sink.send(Message::text(handshake_json)).await?;
        tracing::info!("auth handshake sent");

        // Process incoming messages.
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&text, &mut sink).await {
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

    async fn handle_message(
        &self,
        text: &str,
        sink: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
    ) -> Result<()> {
        let envelope: MeshEnvelope = serde_json::from_str(text)?;

        // Verify signature.
        envelope
            .verify()
            .map_err(|e| anyhow::anyhow!("sig verify: {e}"))?;

        // Check ACL.
        let capability = envelope
            .payload
            .get("capability")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let my_id = self.keypair.agent_id();
        if !self.acl.is_allowed(&envelope.from, &my_id, capability) {
            tracing::warn!(
                from = envelope.from.as_str(),
                capability = capability,
                "ACL denied"
            );
            let err_response = MeshEnvelope::new_signed(
                &self.keypair,
                envelope.from.clone(),
                MessageType::Error,
                serde_json::json!({"error": "acl_denied", "capability": capability, "request_id": envelope.id.to_string()}),
            )?;
            let json = serde_json::to_string(&err_response)?;
            sink.send(Message::text(json)).await?;
            return Ok(());
        }

        // Proxy to local agent.
        let mut response_payload =
            proxy::forward_to_local(&self.local_agent_url, &envelope.payload).await?;

        // Inject request_id so the caller SDK can match this response.
        if let Some(obj) = response_payload.as_object_mut() {
            obj.insert(
                "request_id".into(),
                serde_json::Value::String(envelope.id.to_string()),
            );
        }

        // Send response back through relay.
        let response = MeshEnvelope::new_signed(
            &self.keypair,
            envelope.from,
            MessageType::Response,
            response_payload,
        )?;
        let json = serde_json::to_string(&response)?;
        sink.send(Message::text(json)).await?;
        Ok(())
    }
}
