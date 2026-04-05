pub mod convert;

#[cfg(feature = "mcp-server")]
mod auth;
#[cfg(feature = "mcp-server")]
pub mod inbound;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_mesh_core::agent_card::AgentCard;
use anyhow::Result;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ErrorData as McpError, Implementation,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
    Tool,
};
use rmcp::service::RequestContext;
use rmcp::RoleServer;
use tokio::sync::RwLock;

#[cfg(feature = "mcp-server")]
use self::inbound::InboundQueue;
use crate::daemon::MeshdClient;
use convert::{agent_cards_to_tools, resolve_tool_target};

/// TTL for the agent/tool cache.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// Cached list of agents and their corresponding MCP tools.
struct ToolCache {
    agents: Vec<AgentCard>,
    tools: Vec<Tool>,
    fetched_at: Instant,
}

impl ToolCache {
    fn new() -> Self {
        Self {
            agents: Vec::new(),
            tools: Vec::new(),
            fetched_at: Instant::now() - CACHE_TTL - Duration::from_secs(1),
        }
    }

    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= CACHE_TTL
    }
}

/// MCP server adapter that bridges rmcp and the meshd Local API.
///
/// Dynamically exposes agent capabilities as MCP tools by querying `GET /agents`
/// via `MeshdClient` and caching the result for up to 60 seconds.
/// Built-in tool names for inbound message handling.
const TOOL_GET_MESSAGES: &str = "mesh__get_messages";
const TOOL_REPLY_MESSAGE: &str = "mesh__reply_message";

#[derive(Clone)]
pub struct MeshMcpServer {
    client: Arc<MeshdClient>,
    cache: Arc<RwLock<ToolCache>>,
    /// Inbound message queue (None if receive endpoint is not enabled).
    inbound: Option<InboundQueue>,
}

impl MeshMcpServer {
    /// Create a new `MeshMcpServer` backed by the given `MeshdClient`.
    pub fn new(client: MeshdClient) -> Self {
        Self {
            client: Arc::new(client),
            cache: Arc::new(RwLock::new(ToolCache::new())),
            inbound: None,
        }
    }

    /// Create a new `MeshMcpServer` with inbound message support.
    pub fn with_inbound(client: MeshdClient, inbound: InboundQueue) -> Self {
        Self {
            client: Arc::new(client),
            cache: Arc::new(RwLock::new(ToolCache::new())),
            inbound: Some(inbound),
        }
    }

    /// Refresh the tool cache if stale.
    ///
    /// Uses the clone-then-release pattern (K-4) to avoid holding the lock
    /// across async I/O:
    ///
    /// 1. Acquire read lock → check TTL → release read lock.
    /// 2. If stale: fetch from meshd (no lock held).
    /// 3. Acquire write lock → update cache → release write lock.
    async fn refresh_if_stale(&self) -> Result<()> {
        let needs_refresh = {
            let cache = self.cache.read().await;
            cache.is_stale()
        };

        if needs_refresh {
            let (_status, body) = self.client.get("/agents").await?;
            let agents: Vec<AgentCard> = serde_json::from_value(body)?;
            let tools = agent_cards_to_tools(&agents);

            let mut cache = self.cache.write().await;
            // Re-check staleness after acquiring write lock (another task may have
            // refreshed while we were fetching).
            if cache.is_stale() {
                cache.agents = agents;
                cache.tools = tools;
                cache.fetched_at = Instant::now();
            }
        }

        Ok(())
    }
}

impl ServerHandler for MeshMcpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "agent-mesh-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.refresh_if_stale()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let cache = self.cache.read().await;
        let mut tools = cache.tools.clone();

        // Add inbound tools if receive endpoint is enabled.
        if self.inbound.is_some() {
            tools.push(Tool::new(
                TOOL_GET_MESSAGES,
                "Retrieve pending inbound messages from other mesh agents. Returns an array of messages (may be empty).",
                Arc::new({
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), serde_json::json!("object"));
                    m
                }),
            ));
            tools.push(Tool::new(
                TOOL_REPLY_MESSAGE,
                "Send a reply to a pending inbound message. The reply is delivered back to the calling agent.",
                Arc::new({
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), serde_json::json!("object"));
                    m.insert("properties".into(), serde_json::json!({
                        "message_id": { "type": "string", "description": "ID of the message to reply to (from get_messages)" },
                        "payload": { "type": "object", "description": "Reply payload to send back to the calling agent" }
                    }));
                    m.insert("required".into(), serde_json::json!(["message_id", "payload"]));
                    m
                }),
            ));
        }

        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name: &str = &request.name;

        // ── Inbound tools ────────────────────────────────────────────────
        if let Some(ref queue) = self.inbound {
            if tool_name == TOOL_GET_MESSAGES {
                let messages = queue.drain_messages().await;
                let json = serde_json::to_string(&messages)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                return Ok(CallToolResult::success(vec![Content::text(json)]));
            }
            if tool_name == TOOL_REPLY_MESSAGE {
                let args = request
                    .arguments
                    .as_ref()
                    .ok_or_else(|| McpError::invalid_params("missing arguments", None))?;
                let message_id = args
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("missing message_id", None))?;
                let payload = args
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                let delivered = queue.submit_reply(message_id, payload).await;
                if delivered {
                    return Ok(CallToolResult::success(vec![Content::text(
                        r#"{"status":"sent"}"#,
                    )]));
                } else {
                    return Ok(CallToolResult::error(vec![Content::text(
                        r#"{"error":"message_not_found_or_expired"}"#,
                    )]));
                }
            }
        }

        // ── Outbound tools (agent capabilities) ─────────────────────────
        // 1. Refresh cache if stale.
        self.refresh_if_stale()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // 2. Resolve tool name → (agent_id, capability_name). Release lock immediately (K-4).
        let (agent_id, cap_name) = {
            let cache = self.cache.read().await;
            resolve_tool_target(&request.name, &cache.agents).ok_or_else(|| {
                McpError::invalid_params(format!("unknown tool: {}", request.name), None)
            })?
        };

        // 3. Build the meshd POST /request body.
        let payload = serde_json::Value::Object(request.arguments.unwrap_or_default());
        let body = serde_json::json!({
            "target": agent_id.as_str(),
            "capability": cap_name,
            "payload": payload,
            "timeout_secs": 30u64,
        });

        // 4. Call meshd.
        let (status, resp) = self
            .client
            .post("/request", &body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // 5. Convert response to MCP CallToolResult.
        if !status.is_success() {
            return Ok(CallToolResult::error(vec![Content::text(resp.to_string())]));
        }

        let result_payload = resp.get("payload").cloned().unwrap_or(resp);
        Ok(CallToolResult::success(vec![Content::text(
            result_payload.to_string(),
        )]))
    }
}

/// Start the MCP server over stdio (stdin/stdout).
///
/// Used when Claude Code (or other MCP clients) spawns meshctl as a subprocess.
/// No authentication is needed since the parent process owns the pipes.
///
/// If `receive_port` is provided, a receive HTTP endpoint is started alongside
/// the stdio transport. meshd's `--local-agent` should point to this port.
#[cfg(feature = "mcp-server")]
pub async fn serve_stdio(client: MeshdClient, receive_port: Option<u16>) -> anyhow::Result<()> {
    use rmcp::ServiceExt;

    let server = if let Some(port) = receive_port {
        let queue = InboundQueue::new();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        tokio::spawn(inbound::start_receive_server(addr, queue.clone()));
        MeshMcpServer::with_inbound(client, queue)
    } else {
        MeshMcpServer::new(client)
    };

    let service = server
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("failed to start MCP stdio server: {e}"))?;
    tracing::info!("MCP stdio server running");
    service.waiting().await?;
    Ok(())
}

/// Start the MCP Streamable HTTP server.
///
/// Binds to `listen_addr`, optionally enforces Bearer token authentication,
/// and serves MCP requests via the rmcp Streamable HTTP transport.
///
/// If `receive_port` is provided, a receive HTTP endpoint is started alongside
/// the MCP server. meshd's `--local-agent` should point to this port.
/// Shuts down gracefully on Ctrl-C.
#[cfg(feature = "mcp-server")]
pub async fn serve(
    client: MeshdClient,
    listen_addr: std::net::SocketAddr,
    token: Option<String>,
    receive_port: Option<u16>,
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let server = if let Some(port) = receive_port {
        let queue = InboundQueue::new();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        tokio::spawn(inbound::start_receive_server(addr, queue.clone()));
        MeshMcpServer::with_inbound(client, queue)
    } else {
        MeshMcpServer::new(client)
    };

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(auth::bearer_auth_layer(token));

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = %listen_addr, "MCP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::agent_card::{AgentCard, Capability};
    use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
    use chrono::Utc;

    fn make_card(agent_id: &str, caps: Vec<&str>) -> AgentCard {
        AgentCard {
            id: AgentCardId::new_v4(),
            agent_id: AgentId::from_raw(agent_id.to_string()),
            owner_id: UserId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            group_id: GroupId::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            name: "test-agent".to_string(),
            description: None,
            capabilities: caps
                .into_iter()
                .map(|cn| Capability {
                    name: cn.to_string(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                })
                .collect(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: None,
            online: None,
        }
    }

    /// Verify that resolve_tool_target returns McpError for an unknown tool name.
    #[test]
    fn call_tool_unknown_name_resolves_to_none() {
        let cards = vec![make_card("abcdefgh12345678", vec!["scheduling"])];
        let result = resolve_tool_target("zzzzzzzz__scheduling", &cards);
        assert!(result.is_none(), "unknown prefix should return None");
    }

    #[test]
    fn call_tool_known_name_resolves() {
        let cards = vec![make_card("abcdefgh12345678", vec!["scheduling"])];
        let result = resolve_tool_target("abcdefgh__scheduling", &cards);
        assert!(result.is_some());
        let (aid, cap) = result.unwrap();
        assert_eq!(aid.as_str(), "abcdefgh12345678");
        assert_eq!(cap, "scheduling");
    }
}
