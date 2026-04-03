use std::time::Duration;

use agent_mesh_core::identity::AgentId;
use agent_mesh_core::message::{MeshEnvelope, MessageType};
use agent_mesh_core::noise::{NoiseHandshake, NoiseKeypair};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

use super::{api_error, ApiError, LocalApiState};
use crate::node::{PeerNoise, SharedPending, SharedSessions, SharedSink};

// ── Request / Response types ─────────────────────────────────────────────────

/// Request body for `POST /request`.
#[derive(Debug, Deserialize)]
pub(crate) struct MeshRequestBody {
    /// Target agent ID.
    target: String,
    /// Capability to invoke.
    capability: String,
    /// Request payload (JSON).
    #[serde(default)]
    payload: serde_json::Value,
    /// Timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    30
}

/// Response body for `POST /request`.
#[derive(Debug, Serialize)]
pub(crate) struct MeshRequestResponse {
    /// Response payload from the target agent.
    payload: serde_json::Value,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// `POST /request`
///
/// Send an encrypted capability request to a remote agent via the relay.
/// Performs Noise_XX handshake if no session exists yet.
pub(crate) async fn mesh_request(
    State(state): State<LocalApiState>,
    Json(req): Json<MeshRequestBody>,
) -> Result<Json<MeshRequestResponse>, ApiError> {
    let timeout = Duration::from_secs(req.timeout_secs);

    // 1. Connection check: relay must be connected.
    {
        let guard = state.shared_sink.lock().await;
        if guard.is_none() {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "relay not connected",
            ));
        }
    }

    // 2. Resolve target agent ID.
    let target = AgentId::from_raw(req.target.clone());

    // 3. Build the payload with the capability field injected.
    let full_payload = match req.payload {
        serde_json::Value::Object(mut map) => {
            map.insert(
                "capability".to_string(),
                serde_json::Value::String(req.capability.clone()),
            );
            serde_json::Value::Object(map)
        }
        serde_json::Value::Null => {
            serde_json::json!({ "capability": req.capability })
        }
        other => {
            serde_json::json!({ "capability": req.capability, "data": other })
        }
    };

    // 4. Clone keypair (release lock immediately — clone-then-release, K-4).
    let keypair = state.keypair.read().await.clone();

    // 5. Ensure Noise session (initiator handshake if not yet established).
    ensure_noise_session(
        &target,
        &state.shared_sink,
        &state.shared_sessions,
        &state.shared_pending,
        &state.noise_keypair,
        &keypair,
        timeout,
    )
    .await?;

    // 6. Encrypt payload.
    let plaintext = serde_json::to_vec(&full_payload)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let ciphertext = {
        let mut guard = state.shared_sessions.lock().await;
        let transport = match guard.get_mut(target.as_str()) {
            Some(PeerNoise::Established(t)) => t,
            _ => {
                return Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "noise session missing after handshake",
                ))
            }
        };
        transport
            .encrypt(&plaintext)
            .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("encrypt: {e}")))?
    };

    // 7. Build MeshEnvelope (encrypted request).
    let envelope = MeshEnvelope::new_encrypted(
        &keypair,
        target.clone(),
        MessageType::Request,
        None,
        serde_json::Value::String(ciphertext),
    )
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let msg_id = envelope.id;

    // 8. Register pending oneshot, then send.
    let (tx, rx) = oneshot::channel();
    {
        let mut pending = state.shared_pending.lock().await;
        pending.insert(msg_id, tx);
    }

    let json = serde_json::to_string(&envelope)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    {
        let mut sink_guard = state.shared_sink.lock().await;
        sink_guard
            .as_mut()
            .ok_or_else(|| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "relay disconnected before send",
                )
            })?
            .send(Message::text(json))
            .await
            .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("send: {e}")))?;
    }

    // 9. Wait for response with timeout.
    let response = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(env)) => env,
        Ok(Err(_)) => {
            return Err(api_error(
                StatusCode::GATEWAY_TIMEOUT,
                "response channel closed",
            ))
        }
        Err(_) => {
            // Timeout: clean up pending entry.
            state.shared_pending.lock().await.remove(&msg_id);
            return Err(api_error(StatusCode::GATEWAY_TIMEOUT, "request timed out"));
        }
    };

    // 10. Handle error response.
    if response.msg_type == MessageType::Error {
        let err_msg = if response.encrypted {
            let mut guard = state.shared_sessions.lock().await;
            if let Some(PeerNoise::Established(t)) = guard.get_mut(target.as_str()) {
                match response.payload.as_str().and_then(|s| t.decrypt(s).ok()) {
                    Some(plaintext_bytes) => String::from_utf8_lossy(&plaintext_bytes).to_string(),
                    None => {
                        // decrypt failed — return raw payload so operator can diagnose
                        response.payload.to_string()
                    }
                }
            } else {
                response.payload.to_string()
            }
        } else {
            response.payload.to_string()
        };
        return Err(api_error(StatusCode::BAD_GATEWAY, err_msg));
    }

    // 11. Decrypt response payload.
    let result_payload = if response.encrypted {
        let ciphertext_str = response.payload.as_str().ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encrypted payload not a string",
            )
        })?;
        let plaintext_bytes = {
            let mut guard = state.shared_sessions.lock().await;
            match guard.get_mut(target.as_str()) {
                Some(PeerNoise::Established(t)) => t.decrypt(ciphertext_str).map_err(|e| {
                    api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("decrypt: {e}"))
                })?,
                _ => {
                    return Err(api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "noise session gone after response",
                    ))
                }
            }
        };
        serde_json::from_slice(&plaintext_bytes).map_err(|e| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("json decode: {e}"),
            )
        })?
    } else {
        response.payload
    };

    Ok(Json(MeshRequestResponse {
        payload: result_payload,
    }))
}

// ── Noise handshake ──────────────────────────────────────────────────────────

/// Perform Noise_XX initiator handshake with `target` if no established session exists.
///
/// Lock order: sink → pending (same order as connect_and_serve / handle_handshake).
async fn ensure_noise_session(
    target: &AgentId,
    shared_sink: &SharedSink,
    shared_sessions: &SharedSessions,
    shared_pending: &SharedPending,
    noise_keypair: &NoiseKeypair,
    keypair: &agent_mesh_core::identity::AgentKeypair,
    timeout: Duration,
) -> Result<(), ApiError> {
    // Early return if an established session already exists.
    {
        let guard = shared_sessions.lock().await;
        if matches!(guard.get(target.as_str()), Some(PeerNoise::Established(_))) {
            return Ok(());
        }
    }

    // XX message 1: -> e
    let mut handshake = NoiseHandshake::new_initiator(noise_keypair)
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("noise init: {e}")))?;

    let hs_data1 = handshake
        .write_message()
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("noise write msg1: {e}")))?;

    let msg1 = MeshEnvelope::new_signed(
        keypair,
        target.clone(),
        MessageType::Handshake,
        serde_json::Value::String(hs_data1),
    )
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let msg1_id = msg1.id;

    // Register oneshot for msg2, then send msg1.
    let (tx, rx) = oneshot::channel::<MeshEnvelope>();
    {
        let mut pending = shared_pending.lock().await;
        pending.insert(msg1_id, tx);
    }

    let json1 = serde_json::to_string(&msg1)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    {
        let mut sink_guard = shared_sink.lock().await;
        sink_guard
            .as_mut()
            .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "relay not connected"))?
            .send(Message::text(json1))
            .await
            .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("send msg1: {e}")))?;
    }

    // Wait for msg2 with timeout.
    let msg2 = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(env)) => env,
        Ok(Err(_)) => {
            return Err(api_error(
                StatusCode::GATEWAY_TIMEOUT,
                "handshake msg2 channel closed",
            ))
        }
        Err(_) => {
            shared_pending.lock().await.remove(&msg1_id);
            return Err(api_error(
                StatusCode::GATEWAY_TIMEOUT,
                "handshake timed out",
            ));
        }
    };

    // XX message 2: <- e, ee, s, es
    let hs_data2 = msg2.payload.as_str().ok_or_else(|| {
        api_error(
            StatusCode::BAD_GATEWAY,
            "handshake msg2 payload not a string",
        )
    })?;
    handshake
        .read_message(hs_data2)
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("noise read msg2: {e}")))?;

    // XX message 3: -> s, se
    let hs_data3 = handshake
        .write_message()
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("noise write msg3: {e}")))?;

    let msg3 = MeshEnvelope::new_signed_reply(
        keypair,
        target.clone(),
        MessageType::Handshake,
        Some(msg2.id),
        serde_json::Value::String(hs_data3),
    )
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Send msg3 (no response expected).
    let json3 = serde_json::to_string(&msg3)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    {
        let mut sink_guard = shared_sink.lock().await;
        sink_guard
            .as_mut()
            .ok_or_else(|| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "relay disconnected during handshake",
                )
            })?
            .send(Message::text(json3))
            .await
            .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("send msg3: {e}")))?;
    }

    // Transition to transport mode and store in sessions.
    let transport = handshake
        .into_transport()
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, format!("noise transport: {e}")))?;
    {
        let mut sessions = shared_sessions.lock().await;
        sessions.insert(
            target.as_str().to_string(),
            PeerNoise::Established(transport),
        );
    }

    tracing::info!(
        target = target.as_str(),
        "noise handshake complete (initiator)"
    );
    Ok(())
}
