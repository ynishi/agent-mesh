pub mod convert;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_mesh_core::agent_card::AgentCard;
use anyhow::Result;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    ErrorData as McpError, Implementation, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::RoleServer;
use tokio::sync::RwLock;

use crate::daemon::MeshdClient;
use convert::agent_cards_to_tools;

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
}
