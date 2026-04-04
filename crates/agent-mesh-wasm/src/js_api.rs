//! JavaScript API via wasm-bindgen.
//!
//! Wraps `WasmMeshClient` in a `#[wasm_bindgen]`-compatible interface.
//! All methods return `Promise` (via async + wasm-bindgen-futures).

use wasm_bindgen::prelude::*;

use agent_mesh_core::identity::{AgentId, AgentKeypair};

use crate::client::WasmMeshClient;

/// Mesh client for browser/PWA usage.
///
/// ```js
/// const client = await MeshClient.connect("secret_key_hex", "wss://relay.example.com/relay/ws");
/// console.log(client.agentId());
/// const response = await client.request("target_agent_id", '{"capability":"echo"}');
/// ```
#[wasm_bindgen]
pub struct MeshClient {
    inner: WasmMeshClient,
}

#[wasm_bindgen]
impl MeshClient {
    /// Derive agent ID from a secret key without connecting.
    ///
    /// Useful for registering the agent with the CP before relay connection.
    #[wasm_bindgen(js_name = "deriveAgentId")]
    pub fn derive_agent_id(secret_key_hex: &str) -> Result<String, JsError> {
        let secret_bytes = hex_to_bytes(secret_key_hex)?;
        let keypair = AgentKeypair::from_bytes(&secret_bytes);
        Ok(keypair.agent_id().as_str().to_string())
    }

    /// Connect to the relay with a secret key (hex-encoded Ed25519 signing key).
    ///
    /// Returns a connected, authenticated MeshClient.
    #[wasm_bindgen]
    pub async fn connect(secret_key_hex: &str, relay_url: &str) -> Result<MeshClient, JsError> {
        let secret_bytes = hex_to_bytes(secret_key_hex)?;
        let keypair = AgentKeypair::from_bytes(&secret_bytes);

        let inner = WasmMeshClient::connect(keypair, relay_url)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(MeshClient { inner })
    }

    /// Generate a new keypair and connect.
    ///
    /// Returns the secret key hex via the callback, then connects.
    #[wasm_bindgen(js_name = "generateAndConnect")]
    pub async fn generate_and_connect(relay_url: &str) -> Result<MeshClientWithKey, JsError> {
        let keypair = AgentKeypair::generate();
        let secret_hex = hex::encode(keypair.secret_bytes());
        let agent_id = keypair.agent_id().as_str().to_string();

        let inner = WasmMeshClient::connect(keypair, relay_url)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(MeshClientWithKey {
            client: MeshClient { inner },
            secret_key_hex: secret_hex,
            agent_id,
        })
    }

    /// Get the agent ID (base64url-encoded Ed25519 public key).
    #[wasm_bindgen(js_name = "agentId")]
    pub fn agent_id(&self) -> String {
        self.inner.agent_id().as_str().to_string()
    }

    /// Send an encrypted request to a target agent.
    ///
    /// `target_agent_id` — base64url-encoded Ed25519 public key of the target.
    /// `payload_json` — JSON string to send as the request payload.
    ///
    /// Returns the response as a JSON string.
    #[wasm_bindgen]
    pub async fn request(
        &mut self,
        target_agent_id: &str,
        payload_json: &str,
    ) -> Result<String, JsError> {
        let target = AgentId::from_raw(target_agent_id.to_string());
        let payload: serde_json::Value = serde_json::from_str(payload_json)
            .map_err(|e| JsError::new(&format!("invalid JSON payload: {e}")))?;

        let response = self
            .inner
            .request(&target, payload)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        serde_json::to_string(&response)
            .map_err(|e| JsError::new(&format!("failed to serialize response: {e}")))
    }
}

/// Result of `generateAndConnect` — includes the generated secret key.
#[wasm_bindgen]
pub struct MeshClientWithKey {
    client: MeshClient,
    secret_key_hex: String,
    agent_id: String,
}

#[wasm_bindgen]
impl MeshClientWithKey {
    /// Get the generated secret key (hex-encoded).
    /// Store this securely — it's the agent's identity.
    #[wasm_bindgen(getter, js_name = "secretKeyHex")]
    pub fn secret_key_hex(&self) -> String {
        self.secret_key_hex.clone()
    }

    /// Get the agent ID.
    #[wasm_bindgen(getter, js_name = "agentId")]
    pub fn agent_id(&self) -> String {
        self.agent_id.clone()
    }

    /// Take the client out (consumes this wrapper).
    #[wasm_bindgen(js_name = "intoClient")]
    pub fn into_client(self) -> MeshClient {
        self.client
    }
}

// -- Helpers --

fn hex_to_bytes(hex: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
