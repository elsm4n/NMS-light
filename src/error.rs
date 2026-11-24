use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::crypto::CryptoError;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(&'static str),
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Database(sqlx::Error),
    Crypto(CryptoError),
    Internal,
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if let Some(database_error) = error.as_database_error() {
            if database_error.code().as_deref() == Some("23505") {
                return Self::Conflict;
            }
            if database_error.code().as_deref() == Some("23514") {
                return Self::BadRequest("request violates a data constraint");
            }
        }
        Self::Database(error)
    }
}

impl From<CryptoError> for ApiError {
    fn from(error: CryptoError) -> Self {
        tracing::error!(error = %error, "credential encryption operation failed");
        Self::Crypto(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "insufficient permissions",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource not found"),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "resource conflicts with existing data",
            ),
            Self::Database(error) => {
                tracing::error!(error = %error, "database operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                )
            }
            Self::Crypto(_) | Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error",
            ),
        };

        (
            status,
            Json(json!({"error": {"code": code, "message": message}})),
        )
            .into_response()
    }
}
