use std::{collections::HashSet, net::IpAddr};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, crypto::SecretCipher, error::ApiError, state::AppState};

#[derive(Debug, Serialize, FromRow)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub location: Option<String>,
    pub group_name: Option<String>,
    pub is_enabled: bool,
    pub poll_interval_seconds: i32,
    pub probe_timeout_ms: i32,
    pub tcp_probe_ports: Vec<i32>,
    pub last_status: String,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub has_snmp_credentials: bool,
    pub has_ssh_credentials: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct DevicePage {
    pub items: Vec<DeviceResponse>,
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
}

#[derive(Deserialize)]
pub struct Pagination {
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_per_page")]
    per_page: u32,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    50
}

#[derive(Deserialize)]
pub struct DeviceWrite {
    ip_address: String,
    hostname: Option<String>,
    vendor: Option<String>,
    #[serde(default = "default_device_type")]
    device_type: String,
    location: Option<String>,
    group_name: Option<String>,
    #[serde(default = "default_enabled")]
    is_enabled: bool,
    #[serde(default = "default_poll_interval")]
    poll_interval_seconds: i32,
    #[serde(default = "default_probe_timeout")]
    probe_timeout_ms: i32,
    tcp_probe_ports: Option<Vec<i32>>,

    snmp_version: Option<String>,
    #[serde(default = "default_snmp_port")]
    snmp_port: i32,
    snmp_v2c_community: Option<String>,
    snmp_v3_username: Option<String>,
    snmp_v3_auth_protocol: Option<String>,
    snmp_v3_auth_secret: Option<String>,
    snmp_v3_priv_protocol: Option<String>,
    snmp_v3_priv_secret: Option<String>,

    #[serde(default = "default_ssh_port")]
    ssh_port: i32,
    ssh_username: Option<String>,
    ssh_private_key: Option<String>,
}

fn default_device_type() -> String {
    "other".to_owned()
}
fn default_enabled() -> bool {
    true
}
fn default_poll_interval() -> i32 {
    30
}
fn default_probe_timeout() -> i32 {
    3000
}
fn default_snmp_port() -> i32 {
    161
}
fn default_ssh_port() -> i32 {
    22
}

impl DeviceWrite {
    fn validate(&self) -> Result<IpAddr, ApiError> {
        let ip = self
            .ip_address
            .parse::<IpAddr>()
            .map_err(|_| ApiError::BadRequest("ip_address must be a valid IPv4 or IPv6 address"))?;

        if !["router", "switch", "firewall", "server", "other"].contains(&self.device_type.as_str())
        {
            return Err(ApiError::BadRequest("device_type is not supported"));
        }
        if !(5..=86_400).contains(&self.poll_interval_seconds) {
            return Err(ApiError::BadRequest(
                "poll_interval_seconds must be between 5 and 86400",
            ));
        }
        if !(100..=60_000).contains(&self.probe_timeout_ms) {
            return Err(ApiError::BadRequest(
                "probe_timeout_ms must be between 100 and 60000",
            ));
        }
        if !(1..=65_535).contains(&self.snmp_port) || !(1..=65_535).contains(&self.ssh_port) {
            return Err(ApiError::BadRequest(
                "SNMP and SSH ports must be between 1 and 65535",
            ));
        }
        if let Some(ports) = &self.tcp_probe_ports {
            let mut unique_ports = HashSet::with_capacity(ports.len());
            if ports.len() > 32
                || ports
                    .iter()
                    .any(|port| !(1..=65_535).contains(port) || !unique_ports.insert(port))
            {
                return Err(ApiError::BadRequest(
                    "tcp_probe_ports must contain at most 32 unique ports between 1 and 65535",
                ));
            }
        }

        match self.snmp_version.as_deref() {
            None => {
                if self.snmp_v2c_community.is_some()
                    || self.snmp_v3_username.is_some()
                    || self.snmp_v3_auth_protocol.is_some()
                    || self.snmp_v3_auth_secret.is_some()
                    || self.snmp_v3_priv_protocol.is_some()
                    || self.snmp_v3_priv_secret.is_some()
                {
                    return Err(ApiError::BadRequest(
                        "SNMP credentials require snmp_version",
                    ));
                }
            }
            Some("v2c") => {
                if self.snmp_v2c_community.as_deref().is_none_or(str::is_empty) {
                    return Err(ApiError::BadRequest("SNMP v2c requires a community string"));
                }
                if self
                    .snmp_v2c_community
                    .as_ref()
                    .is_some_and(|value| value.len() > 255)
                    || self.snmp_v3_username.is_some()
                    || self.snmp_v3_auth_protocol.is_some()
                    || self.snmp_v3_auth_secret.is_some()
                    || self.snmp_v3_priv_protocol.is_some()
                    || self.snmp_v3_priv_secret.is_some()
                {
                    return Err(ApiError::BadRequest(
                        "SNMP v2c credential fields are invalid",
                    ));
                }
            }
            Some("v3") => {
                if self.snmp_v3_username.as_deref().is_none_or(str::is_empty)
                    || self
                        .snmp_v3_auth_protocol
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || self
                        .snmp_v3_auth_secret
                        .as_deref()
                        .is_none_or(str::is_empty)
                {
                    return Err(ApiError::BadRequest(
                        "SNMP v3 requires username, authentication protocol, and authentication secret",
                    ));
                }
                if self.snmp_v2c_community.is_some() {
                    return Err(ApiError::BadRequest(
                        "SNMP v3 must not include an SNMP v2c community",
                    ));
                }
                if !["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
                    .contains(&self.snmp_v3_auth_protocol.as_deref().unwrap_or_default())
                {
                    return Err(ApiError::BadRequest(
                        "SNMP v3 authentication protocol is not supported",
                    ));
                }
                if let Some(protocol) = self.snmp_v3_priv_protocol.as_deref() {
                    if !["des", "3des", "aes128", "aes192", "aes256"].contains(&protocol) {
                        return Err(ApiError::BadRequest(
                            "SNMP v3 privacy protocol is not supported",
                        ));
                    }
                    if self
                        .snmp_v3_priv_secret
                        .as_deref()
                        .is_none_or(str::is_empty)
                    {
                        return Err(ApiError::BadRequest(
                            "SNMP v3 privacy protocol requires a privacy secret",
                        ));
                    }
                } else if self.snmp_v3_priv_secret.is_some() {
                    return Err(ApiError::BadRequest(
                        "SNMP v3 privacy secret requires a privacy protocol",
                    ));
                }
                if self
                    .snmp_v3_auth_secret
                    .as_ref()
                    .is_some_and(|value| value.len() > 1024)
                    || self
                        .snmp_v3_priv_secret
                        .as_ref()
                        .is_some_and(|value| value.len() > 1024)
                {
                    return Err(ApiError::BadRequest(
                        "SNMP v3 secrets exceed the supported length",
                    ));
                }
            }
            Some(_) => return Err(ApiError::BadRequest("snmp_version must be v2c or v3")),
        }

        if self.ssh_username.is_some() != self.ssh_private_key.is_some() {
            return Err(ApiError::BadRequest(
                "SSH username and private key must be provided together",
            ));
        }
        if self.ssh_username.as_deref().is_some_and(str::is_empty)
            || self
                .ssh_private_key
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 16_384)
        {
            return Err(ApiError::BadRequest("SSH credential values are invalid"));
        }

        Ok(ip)
    }
}

pub async fn list(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(pagination): Query<Pagination>,
) -> Result<Json<DevicePage>, ApiError> {
    if pagination.page == 0 || !(1..=100).contains(&pagination.per_page) {
        return Err(ApiError::BadRequest(
            "page must be positive and per_page must be between 1 and 100",
        ));
    }
    let offset = i64::from(pagination.page - 1)
        .checked_mul(i64::from(pagination.per_page))
        .ok_or(ApiError::BadRequest("page is out of range"))?;
    let limit = i64::from(pagination.per_page);

    let items = sqlx::query_as!(
        DeviceResponse,
        r#"SELECT
            id,
            host(ip_address) AS "ip_address!",
            hostname,
            vendor,
            device_type,
            location,
            group_name,
            is_enabled,
            poll_interval_seconds,
            probe_timeout_ms,
            tcp_probe_ports as "tcp_probe_ports!",
            last_status,
            last_checked_at,
            last_seen_at,
            (snmp_version IS NOT NULL AND (snmp_v2c_community_ciphertext IS NOT NULL OR snmp_v3_username IS NOT NULL)) AS "has_snmp_credentials!",
            (ssh_private_key_ciphertext IS NOT NULL) AS "has_ssh_credentials!",
            created_at,
            updated_at
         FROM devices
         WHERE deleted_at IS NULL
         ORDER BY ip_address
         LIMIT $1 OFFSET $2"#,
        limit,
        offset
    )
    .fetch_all(&state.db)
    .await?;

    let total = sqlx::query!("SELECT COUNT(*) AS \"count!\" FROM devices WHERE deleted_at IS NULL")
        .fetch_one(&state.db)
        .await?
        .count;

    Ok(Json(DevicePage {
        items,
        page: pagination.page,
        per_page: pagination.per_page,
        total,
    }))
}

pub async fn get_one(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let device = sqlx::query_as!(
        DeviceResponse,
        r#"SELECT
            id,
            host(ip_address) AS "ip_address!",
            hostname,
            vendor,
            device_type,
            location,
            group_name,
            is_enabled,
            poll_interval_seconds,
            probe_timeout_ms,
            tcp_probe_ports as "tcp_probe_ports!",
            last_status,
            last_checked_at,
            last_seen_at,
            (snmp_version IS NOT NULL AND (snmp_v2c_community_ciphertext IS NOT NULL OR snmp_v3_username IS NOT NULL)) AS "has_snmp_credentials!",
            (ssh_private_key_ciphertext IS NOT NULL) AS "has_ssh_credentials!",
            created_at,
            updated_at
         FROM devices
         WHERE id = $1 AND deleted_at IS NULL"#,
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(device))
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<DeviceWrite>,
) -> Result<(StatusCode, Json<DeviceResponse>), ApiError> {
    user.require_inventory_write()?;
    let ip: ipnet::IpNet = request.validate()?.into();
    let id = Uuid::new_v4();
    let snmp_v2c_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v2c_community",
        request.snmp_v2c_community.as_deref(),
    )?;
    let snmp_v3_auth_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v3_auth_secret",
        request.snmp_v3_auth_secret.as_deref(),
    )?;
    let snmp_v3_priv_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v3_priv_secret",
        request.snmp_v3_priv_secret.as_deref(),
    )?;
    let ssh_private_key_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "ssh_private_key",
        request.ssh_private_key.as_deref(),
    )?;

    let device = sqlx::query_as!(
        DeviceResponse,
        r#"INSERT INTO devices (
            id, ip_address, hostname, vendor, device_type, location, group_name,
            is_enabled, poll_interval_seconds, probe_timeout_ms,
            snmp_version, snmp_port, snmp_v2c_community_ciphertext,
            snmp_v3_username, snmp_v3_auth_protocol, snmp_v3_auth_secret_ciphertext,
            snmp_v3_priv_protocol, snmp_v3_priv_secret_ciphertext,
            ssh_port, ssh_username, ssh_private_key_ciphertext, tcp_probe_ports
         ) VALUES (
            $1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
         )
         RETURNING
            id,
            host(ip_address) AS "ip_address!",
            hostname,
            vendor,
            device_type,
            location,
            group_name,
            is_enabled,
            poll_interval_seconds,
            probe_timeout_ms,
            tcp_probe_ports as "tcp_probe_ports!",
            last_status,
            last_checked_at,
            last_seen_at,
            (snmp_version IS NOT NULL AND (snmp_v2c_community_ciphertext IS NOT NULL OR snmp_v3_username IS NOT NULL)) AS "has_snmp_credentials!",
            (ssh_private_key_ciphertext IS NOT NULL) AS "has_ssh_credentials!",
            created_at,
            updated_at"#,
        id,
        ip,
        request.hostname,
        request.vendor,
        request.device_type,
        request.location,
        request.group_name,
        request.is_enabled,
        request.poll_interval_seconds,
        request.probe_timeout_ms,
        request.snmp_version,
        request.snmp_port,
        snmp_v2c_ciphertext,
        request.snmp_v3_username,
        request.snmp_v3_auth_protocol,
        snmp_v3_auth_ciphertext,
        request.snmp_v3_priv_protocol,
        snmp_v3_priv_ciphertext,
        request.ssh_port,
        request.ssh_username,
        ssh_private_key_ciphertext,
        request.tcp_probe_ports.as_deref().unwrap_or(&[])
    )
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(device)))
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<DeviceWrite>,
) -> Result<Json<DeviceResponse>, ApiError> {
    user.require_inventory_write()?;
    let ip: ipnet::IpNet = request.validate()?.into();
    let snmp_v2c_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v2c_community",
        request.snmp_v2c_community.as_deref(),
    )?;
    let snmp_v3_auth_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v3_auth_secret",
        request.snmp_v3_auth_secret.as_deref(),
    )?;
    let snmp_v3_priv_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "snmp_v3_priv_secret",
        request.snmp_v3_priv_secret.as_deref(),
    )?;
    let ssh_private_key_ciphertext = encrypt_optional(
        &state.credential_cipher,
        id,
        "ssh_private_key",
        request.ssh_private_key.as_deref(),
    )?;

    let device = sqlx::query_as!(
        DeviceResponse,
        r#"UPDATE devices SET
            ip_address = $2::inet,
            hostname = $3,
            vendor = $4,
            device_type = $5,
            location = $6,
            group_name = $7,
            is_enabled = $8,
            poll_interval_seconds = $9,
            probe_timeout_ms = $10,
            snmp_version = $11,
            snmp_port = $12,
            snmp_v2c_community_ciphertext = $13,
            snmp_v3_username = $14,
            snmp_v3_auth_protocol = $15,
            snmp_v3_auth_secret_ciphertext = $16,
            snmp_v3_priv_protocol = $17,
            snmp_v3_priv_secret_ciphertext = $18,
            ssh_port = $19,
            ssh_username = $20,
            ssh_private_key_ciphertext = $21,
            tcp_probe_ports = COALESCE($22, tcp_probe_ports),
            updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING
            id,
            host(ip_address) AS "ip_address!",
            hostname,
            vendor,
            device_type,
            location,
            group_name,
            is_enabled,
            poll_interval_seconds,
            probe_timeout_ms,
            tcp_probe_ports as "tcp_probe_ports!",
            last_status,
            last_checked_at,
            last_seen_at,
            (snmp_version IS NOT NULL AND (snmp_v2c_community_ciphertext IS NOT NULL OR snmp_v3_username IS NOT NULL)) AS "has_snmp_credentials!",
            (ssh_private_key_ciphertext IS NOT NULL) AS "has_ssh_credentials!",
            created_at,
            updated_at"#,
        id,
        ip,
        request.hostname,
        request.vendor,
        request.device_type,
        request.location,
        request.group_name,
        request.is_enabled,
        request.poll_interval_seconds,
        request.probe_timeout_ms,
        request.snmp_version,
        request.snmp_port,
        snmp_v2c_ciphertext,
        request.snmp_v3_username,
        request.snmp_v3_auth_protocol,
        snmp_v3_auth_ciphertext,
        request.snmp_v3_priv_protocol,
        snmp_v3_priv_ciphertext,
        request.ssh_port,
        request.ssh_username,
        ssh_private_key_ciphertext,
        request.tcp_probe_ports.as_deref()
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(device))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    user.require_inventory_write()?;
    let result = sqlx::query!(
        "UPDATE devices SET is_enabled = FALSE, deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
        id
    )
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::DeviceWrite;

    fn valid_device() -> DeviceWrite {
        DeviceWrite {
            ip_address: "192.0.2.10".to_owned(),
            hostname: Some("edge-router".to_owned()),
            vendor: None,
            device_type: "router".to_owned(),
            location: None,
            group_name: None,
            is_enabled: true,
            poll_interval_seconds: 30,
            probe_timeout_ms: 3_000,
            tcp_probe_ports: None,
            snmp_version: None,
            snmp_port: 161,
            snmp_v2c_community: None,
            snmp_v3_username: None,
            snmp_v3_auth_protocol: None,
            snmp_v3_auth_secret: None,
            snmp_v3_priv_protocol: None,
            snmp_v3_priv_secret: None,
            ssh_port: 22,
            ssh_username: None,
            ssh_private_key: None,
        }
    }

    #[test]
    fn accepts_ipv4_and_ipv6_addresses() {
        assert!(valid_device().validate().is_ok());

        let mut device = valid_device();
        device.ip_address = "2001:db8::10".to_owned();
        assert!(device.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_addresses_and_out_of_range_values() {
        let mut device = valid_device();
        device.ip_address = "not-an-ip".to_owned();
        assert!(device.validate().is_err());

        let mut device = valid_device();
        device.poll_interval_seconds = 4;
        assert!(device.validate().is_err());

        let mut device = valid_device();
        device.probe_timeout_ms = 99;
        assert!(device.validate().is_err());

        let mut device = valid_device();
        device.snmp_port = 65_536;
        assert!(device.validate().is_err());
    }

    #[test]
    fn validates_tcp_probe_ports_and_bounds_the_configured_work() {
        let mut device = valid_device();
        device.tcp_probe_ports = Some(vec![22, 80, 443]);
        assert!(device.validate().is_ok());

        device.tcp_probe_ports = Some(vec![80, 80]);
        assert!(device.validate().is_err());

        device.tcp_probe_ports = Some(vec![0]);
        assert!(device.validate().is_err());

        device.tcp_probe_ports = Some(vec![65_536]);
        assert!(device.validate().is_err());

        device.tcp_probe_ports = Some((1..=33).collect());
        assert!(device.validate().is_err());
    }

    #[test]
    fn validates_snmp_v2c_and_v3_credentials() {
        let mut v2c = valid_device();
        v2c.snmp_version = Some("v2c".to_owned());
        assert!(v2c.validate().is_err());
        v2c.snmp_v2c_community = Some("community".to_owned());
        assert!(v2c.validate().is_ok());

        let mut v3 = valid_device();
        v3.snmp_version = Some("v3".to_owned());
        v3.snmp_v3_username = Some("monitor".to_owned());
        v3.snmp_v3_auth_protocol = Some("sha256".to_owned());
        v3.snmp_v3_auth_secret = Some("auth-secret".to_owned());
        assert!(v3.validate().is_ok());

        v3.snmp_v3_priv_protocol = Some("aes128".to_owned());
        assert!(v3.validate().is_err());
        v3.snmp_v3_priv_secret = Some("privacy-secret".to_owned());
        assert!(v3.validate().is_ok());
    }

    #[test]
    fn ssh_username_and_private_key_must_be_paired() {
        let mut device = valid_device();
        device.ssh_username = Some("monitor".to_owned());
        assert!(device.validate().is_err());
        device.ssh_private_key = Some("private-key-material".to_owned());
        assert!(device.validate().is_ok());
    }
}

fn encrypt_optional(
    cipher: &SecretCipher,
    device_id: Uuid,
    field: &str,
    plaintext: Option<&str>,
) -> Result<Option<Vec<u8>>, ApiError> {
    plaintext
        .map(|value| {
            let associated_data = format!("device:{device_id}:{field}");
            cipher.encrypt(associated_data.as_bytes(), value.as_bytes())
        })
        .transpose()
        .map_err(ApiError::from)
}
