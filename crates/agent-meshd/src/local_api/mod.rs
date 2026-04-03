use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use agent_mesh_core::agent_card::AgentCard;
use agent_mesh_core::identity::AgentKeypair;
use agent_mesh_core::message::{KeyRotationProof, KeyRotationRequest};
use agent_mesh_core::noise::NoiseKeypair;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

use crate::node::{SharedPending, SharedSessions, SharedSink};

use crate::config::{MeshCredentials, NodeConfig};
use crate::node::NodeState;

mod request;

// ── Shared state ──────────────────────────────────────────────────────────────

/// State shared across all Local API handlers.
#[derive(Clone)]
pub(crate) struct LocalApiState {
    /// Control Plane URL (may be set dynamically via POST /login).
    pub cp_url: Arc<RwLock<Option<String>>>,
    /// Bearer token for CP authentication.
    pub bearer_token: Arc<RwLock<Option<String>>>,
    /// Current daemon state.
    pub node_state: Arc<RwLock<NodeState>>,
    /// HTTP client for CP proxy requests.
    pub http_client: reqwest::Client,
    /// Directory for credential storage (`~/.mesh/`).
    pub mesh_dir: PathBuf,
    /// Peer agent cards received from CP Sync.
    pub peers: Arc<RwLock<Vec<AgentCard>>>,
    /// Revoked key agent IDs received from CP Sync.
    pub revoked_keys: Arc<RwLock<HashSet<String>>>,
    /// Active keypair (hot-reload support).
    pub keypair: Arc<RwLock<AgentKeypair>>,
    /// Pending new keypair during a rotation (None until /rotate is called).
    pub pending_keypair: Arc<RwLock<Option<AgentKeypair>>>,
    /// Notify to force relay reconnect after rotation completes.
    pub relay_cancel: Arc<Notify>,
    /// Path to the on-disk config file (for rewriting secret_key_hex after rotation).
    pub config_path: Option<String>,
    /// Shared WebSocket sink to relay (None when disconnected).
    pub shared_sink: SharedSink,
    /// Shared Noise sessions per peer (PeerNoise: Handshaking | Established).
    pub shared_sessions: SharedSessions,
    /// Pending in-flight request map (message_id → oneshot sender).
    pub shared_pending: SharedPending,
    /// Noise keypair for initiator handshakes.
    pub noise_keypair: Arc<NoiseKeypair>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub(crate) fn router(state: LocalApiState) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/login", post(login_start))
        .route("/login/poll", post(login_poll))
        .route("/agents", post(proxy_agents_create))
        .route("/agents", get(proxy_agents_list))
        .route("/groups", post(proxy_groups_create))
        .route("/groups", get(proxy_groups_list))
        .route("/groups/{id}/members", post(proxy_groups_add_member))
        .route(
            "/groups/{id}/members/{user_id}",
            delete(proxy_groups_remove_member),
        )
        .route("/revocations", post(proxy_revocations_create))
        .route("/setup-keys", post(proxy_setup_keys_create))
        .route("/setup-keys", get(proxy_setup_keys_list))
        .route("/setup-keys/{id}", delete(proxy_setup_keys_revoke))
        .route("/register-with-key", post(proxy_register_with_key))
        .route("/acl", post(proxy_acl_create).get(proxy_acl_list))
        .route("/acl/{id}", delete(proxy_acl_delete))
        .route("/rotate", post(rotate_initiate))
        .route("/rotate/complete", post(rotate_complete))
        .route("/request", post(request::mesh_request))
        .with_state(state)
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(super) struct ApiError {
    error: String,
    code: u16,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

pub(super) fn api_error(status: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError {
        error: msg.into(),
        code: status.as_u16(),
    }
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct StatusResponse {
    state: NodeState,
    cp_url: Option<String>,
    has_token: bool,
    peers_count: usize,
    revoked_count: usize,
    /// Number of peers with online == Some(true).
    online_peers: usize,
}

#[derive(Debug, Deserialize)]
struct LoginStartRequest {
    cp_url: String,
}

#[derive(Debug, Deserialize)]
struct LoginPollRequest {
    device_code: String,
}

#[derive(Debug, Deserialize)]
struct RotateInitiateRequest {
    /// Grace period in seconds during which both old and new keys are valid.
    /// Defaults to 86400 (24h).
    #[serde(default)]
    grace_period_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RotateInitiateResponse {
    card_id: String,
    new_agent_id: String,
    grace_period_secs: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn status(State(state): State<LocalApiState>) -> Json<StatusResponse> {
    let node_state = state.node_state.read().await.clone();
    let cp_url = state.cp_url.read().await.clone();
    let has_token = state.bearer_token.read().await.is_some();
    let peers_guard = state.peers.read().await;
    let peers_count = peers_guard.len();
    let online_peers = peers_guard
        .iter()
        .filter(|p| p.online == Some(true))
        .count();
    drop(peers_guard);
    let revoked_count = state.revoked_keys.read().await.len();
    Json(StatusResponse {
        state: node_state,
        cp_url,
        has_token,
        peers_count,
        revoked_count,
        online_peers,
    })
}

async fn login_start(
    State(state): State<LocalApiState>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Response, ApiError> {
    // Store cp_url in shared state.
    {
        let mut lock = state.cp_url.write().await;
        *lock = Some(req.cp_url.clone());
    }

    // POST /oauth/device to CP.
    let url = format!("{}/oauth/device", req.cp_url.trim_end_matches('/'));
    let resp = state
        .http_client
        .post(&url)
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    // On success, also persist cp_url to credentials file.
    if resp.status().is_success() {
        let existing_token = state.bearer_token.read().await.clone();
        let creds = MeshCredentials {
            bearer_token: existing_token,
            cp_url: Some(req.cp_url.clone()),
        };
        creds
            .save(&state.mesh_dir)
            .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    convert_response(resp).await
}

async fn login_poll(
    State(state): State<LocalApiState>,
    Json(req): Json<LoginPollRequest>,
) -> Result<Response, ApiError> {
    let cp_url = state
        .cp_url
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "cp_url not configured"))?;

    let url = format!("{}/oauth/token", cp_url.trim_end_matches('/'));
    let body = serde_json::json!({ "device_code": req.device_code });

    let resp = state
        .http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    // On success (api_token present), persist token and transition state.
    if status.is_success() {
        if let Some(token) = resp_body.get("api_token").and_then(|v| v.as_str()) {
            let token = token.to_string();

            *state.bearer_token.write().await = Some(token.clone());
            *state.node_state.write().await = NodeState::Authenticated;

            let cp_url_stored = state.cp_url.read().await.clone();
            let creds = MeshCredentials {
                bearer_token: Some(token),
                cp_url: cp_url_stored,
            };
            creds
                .save(&state.mesh_dir)
                .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    // Return the CP response body as-is.
    let axum_status =
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    Response::builder()
        .status(axum_status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&resp_body)
                .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        ))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ── Proxy handlers (thin wrappers around proxy_to_cp) ────────────────────────

async fn proxy_agents_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::POST, "/agents", Some(body)).await
}

async fn proxy_agents_list(State(state): State<LocalApiState>) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::GET, "/agents", None).await
}

async fn proxy_groups_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::POST, "/groups", Some(body)).await
}

async fn proxy_groups_list(State(state): State<LocalApiState>) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::GET, "/groups", None).await
}

async fn proxy_groups_add_member(
    State(state): State<LocalApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(
        &state,
        reqwest::Method::POST,
        &format!("/groups/{id}/members"),
        Some(body),
    )
    .await
}

async fn proxy_groups_remove_member(
    State(state): State<LocalApiState>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(String, String)>,
) -> Result<Response, ApiError> {
    proxy_to_cp(
        &state,
        reqwest::Method::DELETE,
        &format!("/groups/{id}/members/{user_id}"),
        None,
    )
    .await
}

async fn proxy_revocations_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::POST, "/revocations", Some(body)).await
}

async fn proxy_setup_keys_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::POST, "/setup-keys", Some(body)).await
}

async fn proxy_setup_keys_list(State(state): State<LocalApiState>) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::GET, "/setup-keys", None).await
}

async fn proxy_setup_keys_revoke(
    State(state): State<LocalApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Response, ApiError> {
    proxy_to_cp(
        &state,
        reqwest::Method::DELETE,
        &format!("/setup-keys/{id}"),
        None,
    )
    .await
}

async fn proxy_register_with_key(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp_raw(
        &state,
        reqwest::Method::POST,
        "/register-with-key",
        Some(body),
    )
    .await
}

async fn proxy_acl_list(State(state): State<LocalApiState>) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::GET, "/acl", None).await
}

async fn proxy_acl_create(
    State(state): State<LocalApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::POST, "/acl", Some(body)).await
}

async fn proxy_acl_delete(
    State(state): State<LocalApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Response, ApiError> {
    proxy_to_cp(&state, reqwest::Method::DELETE, &format!("/acl/{id}"), None).await
}

// ── Key rotation handlers ─────────────────────────────────────────────────────

/// `POST /rotate`
///
/// Generates a new keypair, signs a `KeyRotationProof` with the current key,
/// proxies `POST /agents/{card_id}/rotate-key` to the CP, and stores the new
/// keypair as pending (applied on `/rotate/complete`).
async fn rotate_initiate(
    State(state): State<LocalApiState>,
    Json(req): Json<RotateInitiateRequest>,
) -> Result<Json<RotateInitiateResponse>, ApiError> {
    // 1. Read current keypair (clone to release lock immediately).
    let current_keypair = state.keypair.read().await.clone();
    let own_agent_id = current_keypair.agent_id();

    // 2. Look up our card_id from peers list.
    let card_id = {
        let peers = state.peers.read().await;
        peers
            .iter()
            .find(|p| p.agent_id == own_agent_id)
            .map(|p| p.id.to_string())
    }
    .ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "own agent card not found in peers list; ensure CP sync is active",
        )
    })?;

    // 3. Generate new keypair.
    let new_keypair = AgentKeypair::generate();
    let new_agent_id = new_keypair.agent_id();

    // 4. Build rotation request with cryptographic proof.
    let proof = KeyRotationProof::new(&current_keypair, &new_agent_id);
    let grace_period_secs = req.grace_period_secs.unwrap_or(86400);

    let rotation_req = KeyRotationRequest {
        card_id: agent_mesh_core::identity::AgentCardId::parse_str(&card_id).map_err(|e| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid card_id format: {e}"),
            )
        })?,
        new_agent_id: new_agent_id.clone(),
        proof,
        grace_period_secs: Some(grace_period_secs),
    };

    // 5. Proxy to CP: POST /agents/{card_id}/rotate-key.
    let cp_url = state
        .cp_url
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "cp_url not configured"))?;
    let token = state
        .bearer_token
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "not authenticated"))?;

    let url = format!(
        "{}/agents/{card_id}/rotate-key",
        cp_url.trim_end_matches('/')
    );
    let body = serde_json::to_value(&rotation_req)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = state
        .http_client
        .post(&url)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let msg = resp.text().await.unwrap_or_default();
        return Err(api_error(
            axum::http::StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("CP rotate-key failed: {msg}"),
        ));
    }

    // 6. Store new keypair as pending.
    *state.pending_keypair.write().await = Some(new_keypair);

    tracing::info!(
        new_agent_id = new_agent_id.as_str(),
        grace_period_secs,
        "key rotation initiated"
    );

    Ok(Json(RotateInitiateResponse {
        card_id,
        new_agent_id: new_agent_id.as_str().to_string(),
        grace_period_secs,
    }))
}

/// `POST /rotate/complete`
///
/// Proxies `POST /agents/{card_id}/complete-rotation` to the CP, then applies
/// the pending keypair, rewrites the config file, and triggers relay reconnect.
async fn rotate_complete(
    State(state): State<LocalApiState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. Take pending keypair (must exist).
    let new_keypair = state.pending_keypair.write().await.take().ok_or_else(|| {
        api_error(
            StatusCode::CONFLICT,
            "no pending rotation; call POST /rotate first",
        )
    })?;

    // 2. Derive card_id from the current (old) keypair before swapping.
    let current_keypair = state.keypair.read().await.clone();
    let own_agent_id = current_keypair.agent_id();

    let card_id = {
        let peers = state.peers.read().await;
        peers
            .iter()
            .find(|p| p.agent_id == own_agent_id)
            .map(|p| p.id.to_string())
    }
    .ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "own agent card not found in peers list",
        )
    })?;

    // 3. Proxy to CP: POST /agents/{card_id}/complete-rotation.
    let cp_url = state
        .cp_url
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "cp_url not configured"))?;
    let token = state
        .bearer_token
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "not authenticated"))?;

    let url = format!(
        "{}/agents/{card_id}/complete-rotation",
        cp_url.trim_end_matches('/')
    );

    let resp = state
        .http_client
        .post(&url)
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let msg = resp.text().await.unwrap_or_default();
        // Re-store pending keypair so the caller can retry.
        *state.pending_keypair.write().await = Some(new_keypair);
        return Err(api_error(
            axum::http::StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("CP complete-rotation failed: {msg}"),
        ));
    }

    // 4. Apply new keypair and rewrite config.
    let new_agent_id = new_keypair.agent_id();
    let new_key_hex = hex::encode(new_keypair.secret_bytes());

    *state.keypair.write().await = new_keypair;

    if let Err(e) = NodeConfig::update_secret_key(state.config_path.as_deref(), &new_key_hex) {
        tracing::warn!(error = %e, "config rewrite failed after key rotation");
    }

    // 5. Trigger relay reconnect with new key.
    state.relay_cancel.notify_one();

    tracing::info!(
        new_agent_id = new_agent_id.as_str(),
        "key rotation completed"
    );

    Ok(Json(serde_json::json!({
        "status": "completed",
        "new_agent_id": new_agent_id.as_str()
    })))
}

// ── Core proxy function ───────────────────────────────────────────────────────

/// Forward a request to the Control Plane, injecting the stored Bearer token.
///
/// Returns an axum `Response` that mirrors the CP response (status + body).
async fn proxy_to_cp(
    state: &LocalApiState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Response, ApiError> {
    let cp_url = state
        .cp_url
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "cp_url not configured"))?;

    let token = state
        .bearer_token
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "not authenticated"))?;

    let url = format!("{}{}", cp_url.trim_end_matches('/'), path);
    let mut req = state.http_client.request(method, &url).bearer_auth(&token);

    if let Some(b) = body {
        req = req.json(&b);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    convert_response(resp).await
}

/// Forward a request to the Control Plane WITHOUT Bearer token injection.
///
/// Used exclusively for `/register-with-key` (Setup Key is in the request body).
/// Callers must NOT use this for any endpoint that requires CP authentication.
async fn proxy_to_cp_raw(
    state: &LocalApiState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Response, ApiError> {
    let cp_url = state
        .cp_url
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "cp_url not configured"))?;

    let url = format!("{}{}", cp_url.trim_end_matches('/'), path);
    let mut req = state.http_client.request(method, &url);

    if let Some(b) = body {
        req = req.json(&b);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    convert_response(resp).await
}

/// Convert a `reqwest::Response` into an `axum::response::Response`.
async fn convert_response(resp: reqwest::Response) -> Result<Response, ApiError> {
    let status = resp.status();
    let axum_status =
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    // Copy content-type header if present.
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;

    let mut builder = Response::builder().status(axum_status);
    if let Some(ct) = content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
    }

    builder
        .body(axum::body::Body::from(bytes))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[cfg(test)]
mod tests;
