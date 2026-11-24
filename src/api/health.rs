use axum::{extract::State, http::StatusCode};

use crate::{error::ApiError, state::AppState};

pub async fn live() -> StatusCode {
    StatusCode::OK
}

pub async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    sqlx::query!("SELECT 1 AS value")
        .fetch_one(&state.db)
        .await?;
    Ok(StatusCode::OK)
}
