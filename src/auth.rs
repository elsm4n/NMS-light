use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::ApiError, state::AppState};

const TOKEN_TTL_SECONDS: u64 = 900;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

impl UserRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn can_modify_inventory(self) -> bool {
        matches!(self, Self::Admin | Self::Operator)
    }
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub role: UserRole,
}

impl AuthUser {
    pub fn require_inventory_write(&self) -> Result<(), ApiError> {
        if self.role.can_modify_inventory() {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenClaims {
    sub: Uuid,
    role: UserRole,
    iat: usize,
    exp: usize,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref())
            .map_err(|_| ApiError::Unauthorized)?;
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| ApiError::Unauthorized)?;

        Ok(Self {
            id: token_data.claims.sub,
            role: token_data.claims.role,
        })
    }
}

pub fn issue_token(
    secret: &[u8],
    user_id: Uuid,
    role: UserRole,
) -> Result<(String, u64), ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Internal)?
        .as_secs();
    let issued_at = usize::try_from(now).map_err(|_| ApiError::Internal)?;
    let expires_at =
        usize::try_from(now.saturating_add(TOKEN_TTL_SECONDS)).map_err(|_| ApiError::Internal)?;
    let claims = TokenClaims {
        sub: user_id,
        role,
        iat: issued_at,
        exp: expires_at,
    };
    let encoding_key = EncodingKey::from_secret(secret).map_err(|_| ApiError::Internal)?;
    let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
        .map_err(|_| ApiError::Internal)?;
    Ok((token, TOKEN_TTL_SECONDS))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(parsed_hash) => parsed_hash,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{hash_password, verify_password};

    #[test]
    fn password_hash_verifies_without_storing_plaintext() -> anyhow::Result<()> {
        let password = "a sufficiently long test password";
        let hash = hash_password(password)?;
        assert_ne!(hash, password);
        assert!(verify_password(password, &hash));
        assert!(!verify_password("incorrect password", &hash));
        Ok(())
    }
}
