//! # agent-mesh-wasm
//!
//! Cross-platform (WASM + native) mesh client.
//!
//! Uses `tokio-tungstenite-wasm` which wraps `web-sys::WebSocket` on wasm32
//! and `tokio-tungstenite` on native — same API for both targets.

mod client;
mod error;
mod js_api;

pub use client::WasmMeshClient;
pub use error::WasmSdkError;
pub use js_api::MeshClient;
