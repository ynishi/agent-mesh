use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use agent_mesh_core::identity::UserId;
use agent_mesh_core::user::{ApiToken, User};

use crate::auth::hash_token;
use crate::AppState;

/// Response from GitHub Device Flow initiation.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceFlowResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Request body for token exchange.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub device_code: String,
}

/// Successful login response containing the issued API token.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub api_token: String,
    pub user_id: UserId,
}

/// GitHub token endpoint response (may contain error or access_token).
#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    // interval adjustment returned by slow_down
    interval: Option<u64>,
}

/// GitHub user info response.
#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
}

/// POST /oauth/device — start GitHub Device Flow.
///
/// Returns device_code, user_code, verification_uri, expires_in, interval
/// directly from GitHub.
pub async fn start_device_flow(
    State(state): State<AppState>,
) -> Result<Json<DeviceFlowResponse>, (StatusCode, String)> {
    let config = state.oauth_config.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured".to_string(),
        )
    })?;

    let resp = state
        .http_client
        .post(&config.device_code_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("scope", "read:user"),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to reach GitHub: {e}"),
            )
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("GitHub returned {status}: {body}"),
        ));
    }

    let device_resp: DeviceFlowResponse = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("failed to parse GitHub response: {e}"),
        )
    })?;

    Ok(Json(device_resp))
}

/// POST /oauth/token — exchange device_code for an API token.
///
/// Forwards the device_code to GitHub. On `authorization_pending` / `slow_down`
/// the GitHub error JSON is returned verbatim (HTTP 200) so the CLI can handle
/// polling. On success, creates/fetches the user and issues an API token.
pub async fn exchange_token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let config = state.oauth_config.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured".to_string(),
        )
    })?;

    // Poll GitHub token endpoint.
    let gh_resp: GitHubTokenResponse = state
        .http_client
        .post(&config.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("device_code", req.device_code.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to reach GitHub: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to parse GitHub response: {e}"),
            )
        })?;

    // If GitHub returned an error (authorization_pending, slow_down, etc.)
    // forward it verbatim so the CLI can handle polling.
    if let Some(error) = gh_resp.error {
        let mut body = serde_json::json!({ "error": error });
        if let Some(desc) = gh_resp.error_description {
            body["error_description"] = serde_json::Value::String(desc);
        }
        if let Some(interval) = gh_resp.interval {
            body["interval"] = serde_json::Value::Number(interval.into());
        }
        return Ok(Json(body));
    }

    let access_token = gh_resp.access_token.ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "GitHub response missing access_token".to_string(),
        )
    })?;

    // Fetch GitHub user info.
    let gh_user: GitHubUser = state
        .http_client
        .get(&config.userinfo_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "agent-mesh-registry")
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to reach GitHub user API: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to parse GitHub user response: {e}"),
            )
        })?;

    let external_id = format!("github:{}", gh_user.id);

    // Find or create the user.
    let user = match state
        .db
        .get_user_by_external_id(&external_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
    {
        Some(existing) => existing,
        None => {
            let new_user = User {
                id: UserId::new_v4(),
                external_id: external_id.clone(),
                provider: "github".to_string(),
                display_name: Some(gh_user.login),
                created_at: chrono::Utc::now(),
            };
            state.db.create_user(&new_user).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to create user: {e}"),
                )
            })?;
            new_user
        }
    };

    // Ensure the user has at least one group.
    state.db.ensure_user_has_group(&user.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to ensure user group: {e}"),
        )
    })?;

    // Issue a new API token.
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = hash_token(&raw_token);
    let api_token = ApiToken {
        token_hash,
        user_id: user.id,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    state.db.create_api_token(&api_token).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create api token: {e}"),
        )
    })?;

    let response = LoginResponse {
        api_token: raw_token,
        user_id: user.id,
    };
    Ok(Json(serde_json::to_value(response).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialization error: {e}"),
        )
    })?))
}
