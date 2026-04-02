use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use agent_mesh_core::user::User;

use crate::auth::AuthUser;
use crate::AppState;

/// GET /users/me — return the authenticated user's profile.
pub async fn get_me(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<User>, (StatusCode, String)> {
    let user = state
        .db
        .get_user_by_id(&user_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "user not found".to_string()))?;

    Ok(Json(user))
}
