use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::{AuthUser, UserRole, issue_token, verify_password},
    error::ApiError,
    state::AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in_seconds: u64,
    role: UserRole,
}

#[derive(FromRow)]
struct LoginRow {
    id: Uuid,
    password_hash: String,
    role: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = request.email.trim().to_lowercase();
    if email.is_empty() || request.password.is_empty() {
        return Err(ApiError::Unauthorized);
    }

    let user = sqlx::query_as!(
        LoginRow,
        "SELECT id, password_hash, role FROM users WHERE lower(email) = $1 AND is_active = TRUE",
        email
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    if !verify_password(&request.password, &user.password_hash) {
        return Err(ApiError::Unauthorized);
    }
    let role = UserRole::parse(&user.role).ok_or(ApiError::Internal)?;
    let (access_token, expires_in_seconds) = issue_token(state.jwt_secret.as_ref(), user.id, role)?;

    Ok(Json(LoginResponse {
        access_token,
        token_type: "Bearer",
        expires_in_seconds,
        role,
    }))
}

#[derive(Serialize)]
pub struct WebSocketTicketResponse {
    ticket: String,
    expires_in_seconds: u32,
    subprotocol: &'static str,
}

pub async fn websocket_ticket(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<WebSocketTicketResponse>, ApiError> {
    let ticket = state
        .issue_ws_ticket(user.id, user.role)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(WebSocketTicketResponse {
        ticket,
        expires_in_seconds: 30,
        subprotocol: "cue-events-v1",
    }))
}
