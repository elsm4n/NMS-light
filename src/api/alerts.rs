use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, error::ApiError, state::AppState};

const SUPPORTED_METRICS: &[&str] = &[
    "icmp_reachable",
    "icmp_latency_ms",
    "tcp_reachable",
    "tcp_connect_latency_ms",
    "snmp_reachable",
    "sys_uptime_seconds",
    "snmp_cpu_percent",
    "snmp_memory_used_percent",
    "snmp_if_in_bps",
    "snmp_if_out_bps",
];

#[derive(Debug, Deserialize)]
pub(super) struct AlertRuleWrite {
    pub(super) name: String,
    pub(super) metric_name: String,
    pub(super) series_key: Option<String>,
    pub(super) comparison: String,
    pub(super) warning_threshold: Option<f64>,
    pub(super) critical_threshold: Option<f64>,
    #[serde(default = "default_consecutive_failures")]
    pub(super) consecutive_failures: i32,
    #[serde(default = "default_recovery_successes")]
    pub(super) recovery_successes: i32,
    #[serde(default = "default_cooldown")]
    pub(super) cooldown_seconds: i32,
    #[serde(default = "empty_selector")]
    pub(super) device_selector: JsonValue,
    #[serde(default)]
    pub(super) endpoint_ids: Vec<Uuid>,
}

fn default_consecutive_failures() -> i32 {
    1
}
fn default_recovery_successes() -> i32 {
    2
}
fn default_cooldown() -> i32 {
    300
}
fn empty_selector() -> JsonValue {
    JsonValue::Object(Default::default())
}

impl AlertRuleWrite {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err(ApiError::BadRequest(
                "name must contain between 1 and 120 characters",
            ));
        }
        if !SUPPORTED_METRICS.contains(&self.metric_name.as_str()) {
            return Err(ApiError::BadRequest(
                "metric_name is not supported by the polling engine",
            ));
        }
        validate_series_key(&self.metric_name, self.series_key.as_deref())?;
        if !(1..=1000).contains(&self.consecutive_failures)
            || !(1..=1000).contains(&self.recovery_successes)
            || !(0..=604_800).contains(&self.cooldown_seconds)
        {
            return Err(ApiError::BadRequest(
                "alert counters or cooldown are out of range",
            ));
        }
        match self.comparison.as_str() {
            "unreachable" => {
                if !matches!(
                    self.metric_name.as_str(),
                    "icmp_reachable" | "tcp_reachable" | "snmp_reachable"
                ) || self.warning_threshold.is_some()
                    || self.critical_threshold.is_some()
                {
                    return Err(ApiError::BadRequest(
                        "unreachable rules require a reachability metric and no thresholds",
                    ));
                }
            }
            "gt" | "gte" | "lt" | "lte" => {
                let Some(critical) = self.critical_threshold else {
                    return Err(ApiError::BadRequest(
                        "numeric rules require critical_threshold",
                    ));
                };
                if !critical.is_finite()
                    || self
                        .warning_threshold
                        .is_some_and(|value| !value.is_finite())
                {
                    return Err(ApiError::BadRequest("thresholds must be finite numbers"));
                }
                if let Some(warning) = self.warning_threshold {
                    let valid_order = if matches!(self.comparison.as_str(), "gt" | "gte") {
                        warning <= critical
                    } else {
                        warning >= critical
                    };
                    if !valid_order {
                        return Err(ApiError::BadRequest(
                            "warning_threshold must not be more severe than critical_threshold",
                        ));
                    }
                }
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "comparison must be gt, gte, lt, lte, or unreachable",
                ));
            }
        }
        validate_selector(&self.device_selector)?;
        if self.endpoint_ids.len() > 100 {
            return Err(ApiError::BadRequest(
                "a rule may reference at most 100 webhook endpoints",
            ));
        }
        let mut unique = HashSet::with_capacity(self.endpoint_ids.len());
        if self.endpoint_ids.iter().any(|id| !unique.insert(*id)) {
            return Err(ApiError::BadRequest("endpoint_ids must be unique"));
        }
        Ok(())
    }
}

async fn validate_endpoint_ids(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    endpoint_ids: &[Uuid],
) -> Result<(), ApiError> {
    if endpoint_ids.is_empty() {
        return Ok(());
    }
    let existing_count = sqlx::query_scalar!(
        r#"SELECT COUNT(*)::bigint AS "count!"
           FROM webhook_endpoints
           WHERE id = ANY($1)"#,
        endpoint_ids
    )
    .fetch_one(&mut **transaction)
    .await?;
    if existing_count != endpoint_ids.len() as i64 {
        return Err(ApiError::BadRequest(
            "endpoint_ids contains an unknown endpoint",
        ));
    }
    Ok(())
}

fn validate_series_key(metric_name: &str, series_key: Option<&str>) -> Result<(), ApiError> {
    match metric_name {
        "tcp_reachable" | "tcp_connect_latency_ms" => {
            if let Some(key) = series_key {
                let Some(port) = key
                    .strip_prefix("port=")
                    .and_then(|value| value.parse::<u16>().ok())
                else {
                    return Err(ApiError::BadRequest("TCP series_key must be port=<port>"));
                };
                if port == 0 || key != format!("port={port}") {
                    return Err(ApiError::BadRequest("TCP series_key must be port=<port>"));
                }
            }
        }
        "snmp_if_in_bps" | "snmp_if_out_bps" => {
            let Some(key) = series_key else {
                return Err(ApiError::BadRequest(
                    "interface metrics require series_key=ifIndex=<index>",
                ));
            };
            let Some(index) = key
                .strip_prefix("ifIndex=")
                .and_then(|value| value.parse::<u32>().ok())
            else {
                return Err(ApiError::BadRequest(
                    "interface metrics require series_key=ifIndex=<index>",
                ));
            };
            if index == 0 || key != format!("ifIndex={index}") {
                return Err(ApiError::BadRequest(
                    "interface metrics require series_key=ifIndex=<index>",
                ));
            }
        }
        _ if series_key.is_some() => {
            return Err(ApiError::BadRequest(
                "scalar metrics do not accept a series_key",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_selector(selector: &JsonValue) -> Result<(), ApiError> {
    let object = selector.as_object().ok_or(ApiError::BadRequest(
        "device_selector must be a JSON object",
    ))?;
    if object
        .keys()
        .any(|key| !["group_name", "device_type", "device_ids"].contains(&key.as_str()))
    {
        return Err(ApiError::BadRequest(
            "device_selector contains an unsupported field",
        ));
    }
    if object.get("group_name").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|text| text.trim().is_empty() || text.chars().count() > 128)
    }) {
        return Err(ApiError::BadRequest(
            "device_selector.group_name must be a non-empty string of at most 128 characters",
        ));
    }
    if let Some(value) = object.get("device_type") {
        if !value
            .as_str()
            .is_some_and(|text| ["router", "switch", "firewall", "server", "other"].contains(&text))
        {
            return Err(ApiError::BadRequest(
                "device_selector.device_type is not supported",
            ));
        }
    }
    if let Some(value) = object.get("device_ids") {
        let ids = value.as_array().ok_or(ApiError::BadRequest(
            "device_selector.device_ids must be an array of UUIDs",
        ))?;
        if ids.len() > 500
            || ids.iter().any(|entry| {
                entry
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .is_none()
            })
        {
            return Err(ApiError::BadRequest(
                "device_selector.device_ids must contain at most 500 valid UUIDs",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, FromRow)]
pub struct AlertRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub metric_name: String,
    pub series_key: Option<String>,
    pub comparison: String,
    pub warning_threshold: Option<f64>,
    pub critical_threshold: Option<f64>,
    pub consecutive_failures: i32,
    pub recovery_successes: i32,
    pub cooldown_seconds: i32,
    pub device_selector: JsonValue,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AlertRuleWrite>,
) -> Result<(StatusCode, Json<AlertRuleResponse>), ApiError> {
    user.require_inventory_write()?;
    request.validate()?;
    let mut transaction = state.db.begin().await?;
    validate_endpoint_ids(&mut transaction, &request.endpoint_ids).await?;
    let rule = sqlx::query_as!(
        AlertRuleResponse,
        r#"INSERT INTO alert_rules (
               name, metric_name, series_key, comparison, warning_threshold, critical_threshold,
               consecutive_failures, recovery_successes, cooldown_seconds, device_selector
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id, name, metric_name, series_key, comparison, warning_threshold, critical_threshold,
                     consecutive_failures, recovery_successes, cooldown_seconds,
                     device_selector as "device_selector: JsonValue", is_enabled, created_at, updated_at"#,
        request.name.trim(),
        request.metric_name,
        request.series_key,
        request.comparison,
        request.warning_threshold,
        request.critical_threshold,
        request.consecutive_failures,
        request.recovery_successes,
        request.cooldown_seconds,
        request.device_selector
    )
    .fetch_one(&mut *transaction)
    .await?;

    for endpoint_id in request.endpoint_ids {
        sqlx::query!(
            "INSERT INTO alert_rule_endpoints (rule_id, endpoint_id) VALUES ($1, $2)",
            rule.id,
            endpoint_id
        )
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn update_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<AlertRuleWrite>,
) -> Result<Json<AlertRuleResponse>, ApiError> {
    user.require_inventory_write()?;
    request.validate()?;
    let mut transaction = state.db.begin().await?;
    let rule = sqlx::query_as!(
        AlertRuleResponse,
        r#"UPDATE alert_rules
           SET name = $2,
               metric_name = $3,
               series_key = $4,
               comparison = $5,
               warning_threshold = $6,
               critical_threshold = $7,
               consecutive_failures = $8,
               recovery_successes = $9,
               cooldown_seconds = $10,
               device_selector = $11,
               updated_at = now()
           WHERE id = $1
           RETURNING id, name, metric_name, series_key, comparison, warning_threshold, critical_threshold,
                     consecutive_failures, recovery_successes, cooldown_seconds,
                     device_selector as "device_selector: JsonValue", is_enabled, created_at, updated_at"#,
        id,
        request.name.trim(),
        request.metric_name,
        request.series_key,
        request.comparison,
        request.warning_threshold,
        request.critical_threshold,
        request.consecutive_failures,
        request.recovery_successes,
        request.cooldown_seconds,
        request.device_selector
    )
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;

    validate_endpoint_ids(&mut transaction, &request.endpoint_ids).await?;
    sqlx::query!("DELETE FROM alert_rule_endpoints WHERE rule_id = $1", id)
        .execute(&mut *transaction)
        .await?;
    for endpoint_id in request.endpoint_ids {
        sqlx::query!(
            "INSERT INTO alert_rule_endpoints (rule_id, endpoint_id) VALUES ($1, $2)",
            id,
            endpoint_id
        )
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(Json(rule))
}

#[derive(Debug, Deserialize)]
pub struct AlertRuleEnabledWrite {
    is_enabled: bool,
}

pub async fn set_rule_enabled(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(request): Json<AlertRuleEnabledWrite>,
) -> Result<Json<AlertRuleResponse>, ApiError> {
    user.require_inventory_write()?;
    let mut transaction = state.db.begin().await?;
    let rule = sqlx::query_as!(
        AlertRuleResponse,
        r#"UPDATE alert_rules
           SET is_enabled = $2, updated_at = now()
           WHERE id = $1
           RETURNING id, name, metric_name, series_key, comparison, warning_threshold, critical_threshold,
                     consecutive_failures, recovery_successes, cooldown_seconds,
                     device_selector as "device_selector: JsonValue", is_enabled, created_at, updated_at"#,
        id,
        request.is_enabled
    )
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    transaction.commit().await?;
    Ok(Json(rule))
}

pub async fn list_rules(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<AlertRuleResponse>>, ApiError> {
    let rules = sqlx::query_as!(
        AlertRuleResponse,
        r#"SELECT id, name, metric_name, series_key, comparison, warning_threshold, critical_threshold,
                  consecutive_failures, recovery_successes, cooldown_seconds,
                  device_selector as "device_selector: JsonValue", is_enabled, created_at, updated_at
           FROM alert_rules ORDER BY created_at DESC LIMIT 500"#
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rules))
}

#[derive(Debug, Serialize, FromRow)]
pub struct AlertResponse {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub device_id: Uuid,
    pub series_key: String,
    pub rule_name: String,
    pub state: String,
    pub current_value: Option<f64>,
    pub consecutive_failures: i32,
    pub consecutive_successes: i32,
    pub last_evaluated_at: Option<DateTime<Utc>>,
    pub state_changed_at: DateTime<Utc>,
    pub opened_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<AlertResponse>>, ApiError> {
    let alerts = sqlx::query_as!(
        AlertResponse,
        r#"SELECT a.id, a.rule_id, a.device_id, a.series_key, r.name AS rule_name, a.state,
                  a.current_value, a.consecutive_failures, a.consecutive_successes,
                  a.last_evaluated_at, a.state_changed_at, a.opened_at, a.resolved_at
           FROM alerts AS a JOIN alert_rules AS r ON r.id = a.rule_id
           ORDER BY a.updated_at DESC LIMIT 500"#
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(alerts))
}

#[derive(Debug, Serialize, FromRow)]
pub struct AlertEventResponse {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub rule_name: String,
    pub device_id: Uuid,
    pub from_state: String,
    pub to_state: String,
    pub metric_value: Option<f64>,
    pub details: JsonValue,
    pub occurred_at: DateTime<Utc>,
}

pub async fn list_events(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<AlertEventResponse>>, ApiError> {
    let events = sqlx::query_as!(
        AlertEventResponse,
        r#"SELECT e.id, e.alert_id, r.name AS rule_name, a.device_id,
                  e.from_state, e.to_state, e.metric_value,
                  e.details as "details: JsonValue", e.occurred_at
           FROM alert_events AS e
           JOIN alerts AS a ON a.id = e.alert_id
           JOIN alert_rules AS r ON r.id = a.rule_id
           ORDER BY e.occurred_at DESC LIMIT 500"#
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(events))
}

#[cfg(test)]
mod tests {
    use super::validate_series_key;

    #[test]
    fn validates_canonical_tcp_and_interface_series_keys() {
        assert!(validate_series_key("tcp_reachable", None).is_ok());
        assert!(validate_series_key("tcp_reachable", Some("port=443")).is_ok());
        assert!(validate_series_key("tcp_reachable", Some("port=0")).is_err());
        assert!(validate_series_key("tcp_reachable", Some("port=0443")).is_err());
        assert!(validate_series_key("snmp_if_in_bps", Some("ifIndex=12")).is_ok());
        assert!(validate_series_key("snmp_if_out_bps", Some("ifIndex=0")).is_err());
        assert!(validate_series_key("snmp_if_out_bps", None).is_err());
        assert!(validate_series_key("snmp_cpu_percent", Some("port=443")).is_err());
    }
}
