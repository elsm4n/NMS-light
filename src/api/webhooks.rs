use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    error::ApiError,
    state::AppState,
    webhook_dispatcher::resolve_public_target,
    webhook_providers::{
        WebhookConfig, is_telegram_bot_token, is_telegram_chat_id, telegram_api_url,
        validate_provider_url,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookWrite {
    name: String,
    #[serde(default = "default_provider")]
    provider: String,
    url: Option<String>,
    bearer_token: Option<String>,
    bot_token: Option<String>,
    chat_id: Option<String>,
}

fn default_provider() -> String {
    "generic".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct WebhookEnabledWrite {
    is_enabled: bool,
}

#[derive(Debug, Serialize, FromRow)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<WebhookWrite>,
) -> Result<(StatusCode, Json<WebhookResponse>), ApiError> {
    user.require_inventory_write()?;
    let (target_url, config) = validate_write(&request)?;
    resolve_public_target(&target_url).await.map_err(|_| {
        ApiError::BadRequest(
            "webhook URL must use HTTPS on port 443 and resolve only to public addresses",
        )
    })?;

    let endpoint_id = Uuid::new_v4();
    let plaintext = serde_json::to_vec(&config).map_err(|_| ApiError::Internal)?;
    let associated_data = format!("webhook:{endpoint_id}:config");
    let ciphertext = state
        .credential_cipher
        .encrypt(associated_data.as_bytes(), &plaintext)?;

    let endpoint = sqlx::query_as!(
        WebhookResponse,
        r#"INSERT INTO webhook_endpoints (id, name, provider, config_ciphertext)
           VALUES ($1, $2, $3, $4)
           RETURNING id, name, provider, is_enabled, created_at, updated_at"#,
        endpoint_id,
        request.name.trim(),
        request.provider.as_str(),
        ciphertext
    )
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(endpoint)))
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<WebhookWrite>,
) -> Result<Json<WebhookResponse>, ApiError> {
    user.require_inventory_write()?;
    let (target_url, config) = validate_write(&request)?;
    resolve_public_target(&target_url).await.map_err(|_| {
        ApiError::BadRequest(
            "webhook URL must use HTTPS on port 443 and resolve only to public addresses",
        )
    })?;

    let plaintext = serde_json::to_vec(&config).map_err(|_| ApiError::Internal)?;
    let associated_data = format!("webhook:{id}:config");
    let ciphertext = state
        .credential_cipher
        .encrypt(associated_data.as_bytes(), &plaintext)?;

    let endpoint = sqlx::query_as!(
        WebhookResponse,
        r#"UPDATE webhook_endpoints
           SET name = $2, provider = $3, config_ciphertext = $4, updated_at = now()
           WHERE id = $1
           RETURNING id, name, provider, is_enabled, created_at, updated_at"#,
        id,
        request.name.trim(),
        request.provider.as_str(),
        ciphertext
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(endpoint))
}

pub async fn set_enabled(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<WebhookEnabledWrite>,
) -> Result<Json<WebhookResponse>, ApiError> {
    user.require_inventory_write()?;

    let endpoint = sqlx::query_as!(
        WebhookResponse,
        r#"UPDATE webhook_endpoints
           SET is_enabled = $2, updated_at = now()
           WHERE id = $1
           RETURNING id, name, provider, is_enabled, created_at, updated_at"#,
        id,
        request.is_enabled
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(endpoint))
}

fn validate_write(request: &WebhookWrite) -> Result<(String, WebhookConfig), ApiError> {
    if request.name.trim().is_empty() || request.name.chars().count() > 120 {
        return Err(ApiError::BadRequest(
            "name must contain between 1 and 120 characters",
        ));
    }
    let validate_url = |url: &str| -> Result<String, ApiError> {
        if url.trim().is_empty() || url.len() > 2048 {
            return Err(ApiError::BadRequest(
                "webhook configuration exceeds the supported length",
            ));
        }
        validate_provider_url(&request.provider, url).map_err(|_| {
            ApiError::BadRequest("webhook URL does not match the selected provider")
        })?;
        Ok(url.to_owned())
    };
    let config = match request.provider.as_str() {
        "generic" => {
            if request.bot_token.is_some() || request.chat_id.is_some() {
                return Err(ApiError::BadRequest(
                    "generic webhooks accept only url and bearer_token configuration",
                ));
            }
            if request
                .bearer_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > 4096)
            {
                return Err(ApiError::BadRequest(
                    "webhook bearer token is empty or exceeds the supported length",
                ));
            }
            let url = validate_url(
                request
                    .url
                    .as_deref()
                    .ok_or(ApiError::BadRequest("generic webhooks require url"))?,
            )?;
            (
                url.clone(),
                WebhookConfig {
                    url: Some(url),
                    bearer_token: request.bearer_token.clone(),
                    bot_token: None,
                    chat_id: None,
                },
            )
        }
        "telegram" => {
            if request.url.is_some() || request.bearer_token.is_some() {
                return Err(ApiError::BadRequest(
                    "Telegram webhooks require bot_token and chat_id only",
                ));
            }
            let bot_token = request
                .bot_token
                .as_deref()
                .filter(|token| is_telegram_bot_token(token))
                .ok_or(ApiError::BadRequest(
                    "Telegram bot_token is invalid or missing",
                ))?;
            let chat_id = request
                .chat_id
                .as_deref()
                .filter(|chat_id| is_telegram_chat_id(chat_id))
                .ok_or(ApiError::BadRequest(
                    "Telegram chat_id is invalid or missing",
                ))?;
            let target_url = telegram_api_url(bot_token);
            validate_url(&target_url)?;
            (
                target_url,
                WebhookConfig {
                    url: None,
                    bearer_token: None,
                    bot_token: Some(bot_token.to_owned()),
                    chat_id: Some(chat_id.to_owned()),
                },
            )
        }
        "slack" | "discord" => {
            if request.bearer_token.is_some()
                || request.bot_token.is_some()
                || request.chat_id.is_some()
            {
                return Err(ApiError::BadRequest(
                    "Slack and Discord webhooks require only their provider URL",
                ));
            }
            let url = validate_url(request.url.as_deref().ok_or(ApiError::BadRequest(
                "Slack and Discord webhooks require url",
            ))?)?;
            (
                url.clone(),
                WebhookConfig {
                    url: Some(url),
                    bearer_token: None,
                    bot_token: None,
                    chat_id: None,
                },
            )
        }
        _ => {
            return Err(ApiError::BadRequest(
                "provider must be generic, telegram, slack, or discord",
            ));
        }
    };
    Ok(config)
}

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<WebhookResponse>>, ApiError> {
    let endpoints = sqlx::query_as!(
        WebhookResponse,
        r#"SELECT id, name, provider, is_enabled, created_at, updated_at
           FROM webhook_endpoints ORDER BY created_at DESC LIMIT 500"#
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(endpoints))
}
