use axum::{Json, extract::State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    alerting::{advance_state, threshold_state},
    auth::AuthUser,
    error::ApiError,
    state::AppState,
    webhook_providers::{
        GenericWebhookPayload, WebhookConfig, generic_payload, provider_payload, request_url,
        validate_provider_url,
    },
};

use super::alerts::AlertRuleWrite;

const MAX_RANGE: Duration = Duration::days(7);
const MAX_SAMPLES: i64 = 500;

#[derive(Debug, Deserialize)]
pub(super) struct AlertPreflightRequest {
    rule: AlertRuleWrite,
    device_id: Uuid,
    endpoint_id: Uuid,
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct MetricSample {
    observed_at: DateTime<Utc>,
    value: f64,
}

#[derive(Debug, FromRow)]
struct WebhookEndpointRow {
    provider: String,
    config_ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Clone)]
struct AlertTransition {
    occurred_at: DateTime<Utc>,
    metric_value: Option<f64>,
    from_state: String,
    to_state: String,
}

#[derive(Debug, Serialize)]
struct SampleGap {
    after: DateTime<Utc>,
    before: DateTime<Utc>,
    gap_seconds: i64,
}

#[derive(Debug, Serialize)]
struct SampleCoverage {
    sample_count: usize,
    estimated_expected_samples: usize,
    estimated_coverage_percent: f64,
    internal_gap_count: usize,
    gap_threshold_seconds: i64,
    internal_gaps: Vec<SampleGap>,
}

#[derive(Debug, Serialize)]
struct NotificationPreview {
    provider: String,
    example_only: bool,
    secret_fields_excluded: Vec<&'static str>,
    payload: JsonValue,
}

#[derive(Debug, Serialize)]
struct PreflightRange {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub(super) struct AlertPreflightResponse {
    device_id: Uuid,
    metric_name: String,
    series_key: String,
    range: PreflightRange,
    sample_coverage: SampleCoverage,
    transitions: Vec<AlertTransition>,
    notification_preview: NotificationPreview,
    preview_note: &'static str,
}

pub(super) async fn preflight(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<AlertPreflightRequest>,
) -> Result<Json<AlertPreflightResponse>, ApiError> {
    user.require_inventory_write()?;
    request.rule.validate()?;
    validate_preflight_window(request.start_at, request.end_at, Utc::now())?;
    validate_endpoint_selection(request.endpoint_id, &request.rule.endpoint_ids)?;

    let poll_interval_seconds = sqlx::query_scalar!(
        r#"SELECT d.poll_interval_seconds
           FROM devices AS d
           WHERE d.id = $1
             AND d.is_enabled = TRUE
             AND d.deleted_at IS NULL
             AND (NOT ($2::jsonb ? 'group_name')
                  OR d.group_name = $2::jsonb->>'group_name')
             AND (NOT ($2::jsonb ? 'device_type')
                  OR d.device_type = $2::jsonb->>'device_type')
             AND (NOT ($2::jsonb ? 'device_ids')
                  OR ($2::jsonb->'device_ids' ? d.id::text))"#,
        request.device_id,
        &request.rule.device_selector
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    let endpoint = sqlx::query_as!(
        WebhookEndpointRow,
        r#"SELECT provider, config_ciphertext
           FROM webhook_endpoints
           WHERE id = $1"#,
        request.endpoint_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let associated_data = format!("webhook:{}:config", request.endpoint_id);
    let plaintext = state
        .credential_cipher
        .decrypt(associated_data.as_bytes(), &endpoint.config_ciphertext)
        .map_err(|_| ApiError::Internal)?;
    let credentials: WebhookConfig =
        serde_json::from_slice(&plaintext).map_err(|_| ApiError::Internal)?;
    validate_endpoint_config(&endpoint.provider, &credentials)?;

    let series_key = request.rule.series_key.as_deref().unwrap_or("");
    let samples = sqlx::query_as!(
        MetricSample,
        r#"SELECT observed_at, value
           FROM metrics
           WHERE device_id = $1
             AND metric_name = $2
             AND series_key = $3
             AND observed_at >= $4
             AND observed_at <= $5
           ORDER BY observed_at ASC
           LIMIT $6"#,
        request.device_id,
        request.rule.metric_name,
        series_key,
        request.start_at,
        request.end_at,
        MAX_SAMPLES + 1
    )
    .fetch_all(&state.db)
    .await?;
    validate_sample_count(&samples)?;
    if samples.iter().any(|sample| !sample.value.is_finite()) {
        return Err(ApiError::BadRequest(
            "histori memuat nilai metrik non-finit dan tidak dapat dipratinjau",
        ));
    }

    let transitions = replay_samples(&request.rule, &samples);
    let sample_coverage = sample_coverage(
        request.start_at,
        request.end_at,
        poll_interval_seconds,
        &samples,
    );
    let example_only = transitions.is_empty();
    let preview_transition = transitions
        .first()
        .cloned()
        .unwrap_or_else(|| AlertTransition {
            occurred_at: samples
                .last()
                .map(|sample| sample.observed_at)
                .unwrap_or(request.end_at),
            metric_value: samples.last().map(|sample| sample.value),
            from_state: "ok".to_owned(),
            to_state: "warning".to_owned(),
        });
    let notification_preview = render_notification_preview(
        &endpoint.provider,
        &credentials,
        &request.rule,
        request.device_id,
        &preview_transition,
        example_only,
    )?;

    Ok(Json(AlertPreflightResponse {
        device_id: request.device_id,
        metric_name: request.rule.metric_name,
        series_key: series_key.to_owned(),
        range: PreflightRange {
            start_at: request.start_at,
            end_at: request.end_at,
        },
        sample_coverage,
        transitions,
        notification_preview,
        preview_note: if example_only {
            "Tidak ada transisi pada histori ini; payload hanya contoh format, bukan notifikasi yang diprediksi."
        } else {
            "ID alert pada payload adalah penanda preview; ID aktual dibuat saat transisi live."
        },
    }))
}

fn validate_preflight_window(
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if end_at <= start_at {
        return Err(ApiError::BadRequest("end_at harus setelah start_at"));
    }
    if end_at.signed_duration_since(start_at) > MAX_RANGE {
        return Err(ApiError::BadRequest(
            "rentang waktu preflight tidak boleh melebihi 7 hari",
        ));
    }
    if end_at > now {
        return Err(ApiError::BadRequest("end_at harus berada di masa lalu"));
    }
    Ok(())
}

fn validate_endpoint_selection(endpoint_id: Uuid, endpoint_ids: &[Uuid]) -> Result<(), ApiError> {
    if endpoint_ids.contains(&endpoint_id) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "endpoint_id harus tercantum dalam endpoint_ids pada draft rule",
        ))
    }
}

fn validate_sample_count(samples: &[MetricSample]) -> Result<(), ApiError> {
    if samples.len() <= MAX_SAMPLES as usize {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "histori berisi lebih dari 500 sampel; persempit rentang waktu",
        ))
    }
}

fn validate_endpoint_config(provider: &str, credentials: &WebhookConfig) -> Result<(), ApiError> {
    let url = request_url(provider, credentials)
        .map_err(|_| ApiError::BadRequest("konfigurasi webhook yang dipilih tidak valid"))?;
    validate_provider_url(provider, &url)
        .map_err(|_| ApiError::BadRequest("konfigurasi webhook yang dipilih tidak valid"))
}

fn replay_samples(rule: &AlertRuleWrite, samples: &[MetricSample]) -> Vec<AlertTransition> {
    let mut state = "ok".to_owned();
    let mut failures = 0;
    let mut successes = 0;
    let mut transitions = Vec::new();

    for sample in samples {
        let target_state = threshold_state(
            &rule.comparison,
            sample.value,
            rule.warning_threshold,
            rule.critical_threshold,
        );
        let progress = advance_state(
            &state,
            failures,
            successes,
            target_state,
            rule.consecutive_failures,
            rule.recovery_successes,
        );
        if progress.state != state {
            transitions.push(AlertTransition {
                occurred_at: sample.observed_at,
                metric_value: Some(sample.value),
                from_state: state,
                to_state: progress.state.clone(),
            });
        }
        state = progress.state;
        failures = progress.consecutive_failures;
        successes = progress.consecutive_successes;
    }
    transitions
}

fn sample_coverage(
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    poll_interval_seconds: i32,
    samples: &[MetricSample],
) -> SampleCoverage {
    let interval = i64::from(poll_interval_seconds.max(1));
    let range_seconds = end_at.signed_duration_since(start_at).num_seconds().max(1);
    let expected = ((range_seconds as f64) / (interval as f64)).ceil() as usize;
    let estimated_coverage_percent = if expected == 0 {
        0.0
    } else {
        ((samples.len() as f64 / expected as f64) * 100.0).min(100.0)
    };
    let gap_threshold_seconds = interval.saturating_mul(2);
    let internal_gaps = samples
        .windows(2)
        .filter_map(|pair| {
            let gap_seconds = pair[1]
                .observed_at
                .signed_duration_since(pair[0].observed_at)
                .num_seconds();
            (gap_seconds > gap_threshold_seconds).then_some(SampleGap {
                after: pair[0].observed_at,
                before: pair[1].observed_at,
                gap_seconds,
            })
        })
        .collect::<Vec<_>>();
    SampleCoverage {
        sample_count: samples.len(),
        estimated_expected_samples: expected,
        estimated_coverage_percent,
        internal_gap_count: internal_gaps.len(),
        gap_threshold_seconds,
        internal_gaps,
    }
}

fn render_notification_preview(
    provider: &str,
    credentials: &WebhookConfig,
    rule: &AlertRuleWrite,
    device_id: Uuid,
    transition: &AlertTransition,
    example_only: bool,
) -> Result<NotificationPreview, ApiError> {
    let series_key = rule.series_key.as_deref().unwrap_or("");
    let details = json!({
        "rule_name": rule.name.trim(),
        "metric_name": rule.metric_name,
        "series_key": series_key,
        "comparison": rule.comparison
    });
    let mut payload = if provider == "generic" {
        generic_payload(GenericWebhookPayload {
            event_id: Uuid::nil(),
            alert_id: Uuid::nil(),
            rule_id: Uuid::nil(),
            device_id,
            rule_name: rule.name.trim(),
            from_state: &transition.from_state,
            to_state: &transition.to_state,
            metric_value: transition.metric_value,
            details,
            occurred_at: transition.occurred_at,
        })
    } else {
        provider_payload(
            provider,
            credentials.chat_id.as_deref(),
            Uuid::nil(),
            device_id,
            rule.name.trim(),
            Some(&rule.metric_name),
            Some(series_key),
            &transition.from_state,
            &transition.to_state,
            transition.metric_value,
        )
        .map_err(|_| ApiError::BadRequest("konfigurasi webhook yang dipilih tidak valid"))?
    };
    let secret_fields_excluded = match provider {
        "telegram" => {
            if let Some(object) = payload.as_object_mut() {
                object.insert(
                    "chat_id".to_owned(),
                    JsonValue::String("[REDACTED]".to_owned()),
                );
            }
            vec!["chat_id"]
        }
        "generic" => vec!["url", "bearer_token"],
        "slack" | "discord" => vec!["url"],
        _ => {
            return Err(ApiError::BadRequest(
                "provider webhook yang dipilih tidak didukung",
            ));
        }
    };
    Ok(NotificationPreview {
        provider: provider.to_owned(),
        example_only,
        secret_fields_excluded,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use tokio::{net::TcpListener, time};
    use uuid::Uuid;

    use crate::{api::alerts::AlertRuleWrite, webhook_providers::WebhookConfig};

    use super::{
        AlertTransition, MetricSample, render_notification_preview, replay_samples,
        sample_coverage, validate_endpoint_config, validate_endpoint_selection,
        validate_preflight_window, validate_sample_count,
    };

    fn test_rule() -> AlertRuleWrite {
        AlertRuleWrite {
            name: "CPU high".to_owned(),
            metric_name: "snmp_cpu_percent".to_owned(),
            series_key: None,
            comparison: "gte".to_owned(),
            warning_threshold: Some(70.0),
            critical_threshold: Some(90.0),
            consecutive_failures: 2,
            recovery_successes: 2,
            cooldown_seconds: 300,
            device_selector: json!({}),
            endpoint_ids: vec![Uuid::nil()],
        }
    }

    fn timestamp(seconds: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .unwrap_or_else(Utc::now)
    }

    fn generic_config(url: String) -> WebhookConfig {
        WebhookConfig {
            url: Some(url),
            bearer_token: Some("bearer-secret-for-test".to_owned()),
            bot_token: None,
            chat_id: None,
        }
    }

    #[test]
    fn validates_the_seven_day_history_window() {
        let now = timestamp(2_000_000);
        assert!(validate_preflight_window(now - chrono::Duration::days(7), now, now).is_ok());
        assert!(
            validate_preflight_window(
                now - chrono::Duration::days(7) - chrono::Duration::seconds(1),
                now,
                now
            )
            .is_err()
        );
        assert!(validate_preflight_window(now, now, now).is_err());
        assert!(
            validate_preflight_window(
                now - chrono::Duration::hours(1),
                now + chrono::Duration::seconds(1),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn enforces_sample_limit_and_selected_endpoint() {
        let samples = std::iter::repeat_with(|| MetricSample {
            observed_at: timestamp(1),
            value: 1.0,
        })
        .take(501)
        .collect::<Vec<_>>();
        assert!(validate_sample_count(&samples[..500]).is_ok());
        assert!(validate_sample_count(&samples).is_err());

        let selected = Uuid::new_v4();
        assert!(validate_endpoint_selection(selected, &[selected]).is_ok());
        assert!(validate_endpoint_selection(Uuid::new_v4(), &[selected]).is_err());
    }

    #[test]
    fn replay_reports_warning_critical_and_recovery_transitions() {
        let rule = test_rule();
        let samples = [
            MetricSample {
                observed_at: timestamp(1),
                value: 75.0,
            },
            MetricSample {
                observed_at: timestamp(2),
                value: 75.0,
            },
            MetricSample {
                observed_at: timestamp(3),
                value: 95.0,
            },
            MetricSample {
                observed_at: timestamp(4),
                value: 95.0,
            },
            MetricSample {
                observed_at: timestamp(5),
                value: 10.0,
            },
            MetricSample {
                observed_at: timestamp(6),
                value: 10.0,
            },
        ];
        let transitions = replay_samples(&rule, &samples);
        assert_eq!(
            transitions
                .iter()
                .map(|item| item.to_state.as_str())
                .collect::<Vec<_>>(),
            ["warning", "critical", "resolved"]
        );
        assert_eq!(transitions[0].from_state, "ok");
        assert_eq!(transitions[2].from_state, "critical");
    }

    #[test]
    fn coverage_reports_estimate_and_internal_sample_gaps() {
        let samples = [
            MetricSample {
                observed_at: timestamp(0),
                value: 1.0,
            },
            MetricSample {
                observed_at: timestamp(30),
                value: 1.0,
            },
            MetricSample {
                observed_at: timestamp(150),
                value: 1.0,
            },
        ];
        let coverage = sample_coverage(timestamp(0), timestamp(180), 30, &samples);
        assert_eq!(coverage.sample_count, 3);
        assert_eq!(coverage.estimated_expected_samples, 6);
        assert_eq!(coverage.internal_gap_count, 1);
        assert_eq!(coverage.internal_gaps[0].gap_seconds, 120);
    }

    #[test]
    fn telegram_preview_redacts_all_endpoint_secrets() -> anyhow::Result<()> {
        let secrets = [
            "https://hooks.example.invalid/secret-url",
            "bearer-secret-for-test",
            "123456:telegram-bot-secret",
            "-1001234567890",
        ];
        let credentials = WebhookConfig {
            url: Some(secrets[0].to_owned()),
            bearer_token: Some(secrets[1].to_owned()),
            bot_token: Some(secrets[2].to_owned()),
            chat_id: Some(secrets[3].to_owned()),
        };
        let transition = AlertTransition {
            occurred_at: timestamp(10),
            metric_value: Some(95.0),
            from_state: "ok".to_owned(),
            to_state: "critical".to_owned(),
        };
        let preview = render_notification_preview(
            "telegram",
            &credentials,
            &test_rule(),
            Uuid::nil(),
            &transition,
            false,
        )
        .map_err(|error| anyhow::anyhow!("preview rendering failed: {error:?}"))?;
        let serialized = serde_json::to_string(&preview)?;
        for secret in secrets {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(preview.payload["chat_id"], "[REDACTED]");
        assert_eq!(preview.secret_fields_excluded, ["chat_id"]);
        Ok(())
    }

    #[test]
    fn validates_provider_target_without_sending_a_request() {
        let config = generic_config("https://127.0.0.1/hook".to_owned());
        assert!(validate_endpoint_config("generic", &config).is_ok());
    }

    #[tokio::test]
    async fn preview_rendering_makes_no_http_request() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let credentials = generic_config(format!("https://{address}/hook"));
        let transition = AlertTransition {
            occurred_at: timestamp(10),
            metric_value: Some(95.0),
            from_state: "ok".to_owned(),
            to_state: "critical".to_owned(),
        };
        let preview = render_notification_preview(
            "generic",
            &credentials,
            &test_rule(),
            Uuid::nil(),
            &transition,
            false,
        )
        .map_err(|error| anyhow::anyhow!("preview rendering failed: {error:?}"))?;
        assert_eq!(preview.provider, "generic");
        assert!(
            !preview
                .payload
                .to_string()
                .contains("bearer-secret-for-test")
        );
        assert!(
            credentials
                .url
                .as_deref()
                .is_some_and(|url| { !preview.payload.to_string().contains(url) })
        );
        assert!(
            time::timeout(StdDuration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod side_effect_tests {
    use chrono::{Duration, Utc};
    use ipnet::IpNet;
    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::{
        auth::{AuthUser, UserRole},
        crypto::SecretCipher,
        state::AppState,
        webhook_providers::WebhookConfig,
    };

    use super::{AlertPreflightRequest, preflight};

    #[tokio::test]
    #[ignore = "memerlukan basis data PostgreSQL khusus yang sudah dimigrasikan"]
    async fn preflight_does_not_write_alert_tables() -> anyhow::Result<()> {
        let database_url = std::env::var("NMS_PREFLIGHT_TEST_DATABASE_URL")?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await?;
        let cipher = SecretCipher::new([47_u8; 32]);
        let state = AppState::new(
            pool.clone(),
            vec![7_u8; 32],
            cipher.clone(),
            Vec::<IpNet>::new(),
            1,
            CancellationToken::new(),
        );
        let device_id = Uuid::new_v4();
        let endpoint_id = Uuid::new_v4();
        let observed_at = Utc::now() - Duration::seconds(30);
        let start_at = Utc::now() - Duration::minutes(2);
        let end_at = Utc::now() - Duration::seconds(5);
        let config = serde_json::to_vec(&WebhookConfig {
            url: Some("https://127.0.0.1/hook".to_owned()),
            bearer_token: Some("must-not-be-returned".to_owned()),
            bot_token: None,
            chat_id: None,
        })?;
        let associated_data = format!("webhook:{endpoint_id}:config");
        let ciphertext = cipher.encrypt(associated_data.as_bytes(), &config)?;

        sqlx::query(
            "INSERT INTO devices (id, ip_address, device_type) VALUES ($1, $2::inet, 'server')",
        )
        .bind(device_id)
        .bind("198.51.100.11")
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO webhook_endpoints (id, name, provider, config_ciphertext) VALUES ($1, 'preflight test', 'generic', $2)",
        )
        .bind(endpoint_id)
        .bind(ciphertext)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO metrics (observed_at, device_id, metric_name, series_key, value, unit, labels) VALUES ($1, $2, 'snmp_cpu_percent', '', 85, 'percent', '{}'::jsonb)",
        )
        .bind(observed_at)
        .bind(device_id)
        .execute(&pool)
        .await?;

        let before = alert_table_counts(&pool).await?;
        assert_eq!(before, (0, 0, 0));
        let request = AlertPreflightRequest {
            rule: super::super::alerts::AlertRuleWrite {
                name: "CPU tinggi".to_owned(),
                metric_name: "snmp_cpu_percent".to_owned(),
                series_key: None,
                comparison: "gte".to_owned(),
                warning_threshold: Some(70.0),
                critical_threshold: Some(90.0),
                consecutive_failures: 1,
                recovery_successes: 2,
                cooldown_seconds: 300,
                device_selector: json!({}),
                endpoint_ids: vec![endpoint_id],
            },
            device_id,
            endpoint_id,
            start_at,
            end_at,
        };
        let response = preflight(
            axum::extract::State(state),
            AuthUser {
                id: Uuid::new_v4(),
                role: UserRole::Admin,
            },
            axum::Json(request),
        )
        .await
        .map_err(|error| anyhow::anyhow!("preflight handler failed: {error:?}"))?;
        assert_eq!(response.0.transitions.len(), 1);
        assert_eq!(response.0.transitions[0].to_state, "warning");
        assert_eq!(alert_table_counts(&pool).await?, before);

        sqlx::query("DELETE FROM metrics WHERE device_id = $1")
            .bind(device_id)
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
            .bind(endpoint_id)
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM devices WHERE id = $1")
            .bind(device_id)
            .execute(&pool)
            .await?;
        pool.close().await;
        Ok(())
    }

    async fn alert_table_counts(pool: &PgPool) -> anyhow::Result<(i64, i64, i64)> {
        let alerts = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alerts")
            .fetch_one(pool)
            .await?;
        let events = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alert_events")
            .fetch_one(pool)
            .await?;
        let outbox = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(pool)
            .await?;
        Ok((alerts, events, outbox))
    }
}
