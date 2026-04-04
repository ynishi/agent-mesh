pub mod commands;
pub mod cp_client;
pub mod daemon;
#[cfg(feature = "mcp-server")]
pub mod mcp_server;

/// Default Control Plane URL (official hosted instance).
pub const DEFAULT_CP_URL: &str = "https://agent-mesh.fly.dev";
