pub mod convert;

#[cfg(feature = "mcp-server")]
mod auth;

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
#[derive(Clone)]
pub struct MeshMcpServer {
    client: Arc<MeshdClient>,
    cache: Arc<RwLock<ToolCache>>,
}

impl MeshMcpServer {
    /// Create a new `MeshMcpServer` backed by the given `MeshdClient`.
    pub fn new(client: MeshdClient) -> Self {
        Self {
            client: Arc::new(client),
            cache: Arc::new(RwLock::new(ToolCache::new())),
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
        Ok(ListToolsResult::with_all_items(cache.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
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
#[cfg(feature = "mcp-server")]
pub async fn serve_stdio(client: MeshdClient) -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    let server = MeshMcpServer::new(client);
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
/// Shuts down gracefully on Ctrl-C.
#[cfg(feature = "mcp-server")]
pub async fn serve(
    client: MeshdClient,
    listen_addr: std::net::SocketAddr,
    token: Option<String>,
) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let server = MeshMcpServer::new(client);
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
