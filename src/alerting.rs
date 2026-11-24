use chrono::{DateTime, Utc};
use serde_json::{Value as JsonValue, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug)]
struct AlertRule {
    id: Uuid,
    name: String,
    comparison: String,
    warning_threshold: Option<f64>,
    critical_threshold: Option<f64>,
    consecutive_failures: i32,
    recovery_successes: i32,
    cooldown_seconds: i32,
}

#[derive(Debug)]
struct AlertStateRow {
    state: String,
    consecutive_failures: i32,
    consecutive_successes: i32,
    last_notified_at: Option<DateTime<Utc>>,
}

pub async fn evaluate_metric(
    transaction: &mut Transaction<'_, Postgres>,
    device_id: Uuid,
    metric_name: &str,
    series_key: &str,
    metric_value: f64,
    observed_at: DateTime<Utc>,
) -> Result<Vec<JsonValue>, sqlx::Error> {
    let rules = sqlx::query_as!(
        AlertRule,
        r#"SELECT r.id, r.name, r.comparison, r.warning_threshold, r.critical_threshold,
                  r.consecutive_failures, r.recovery_successes, r.cooldown_seconds
           FROM alert_rules AS r
           JOIN devices AS d ON d.id = $2
           WHERE r.is_enabled = TRUE
             AND r.metric_name = $1
             AND COALESCE(r.series_key, '') = $3
             AND (NOT (r.device_selector ? 'group_name')
                  OR d.group_name = r.device_selector->>'group_name')
             AND (NOT (r.device_selector ? 'device_type')
                  OR d.device_type = r.device_selector->>'device_type')
             AND (NOT (r.device_selector ? 'device_ids')
                  OR r.device_selector->'device_ids' ? d.id::text)
           ORDER BY r.id"#,
        metric_name,
        device_id,
        series_key
    )
    .fetch_all(&mut **transaction)
    .await?;

    let mut events = Vec::new();
    for rule in rules {
        let previous = sqlx::query_as!(
            AlertStateRow,
            r#"SELECT state, consecutive_failures, consecutive_successes, last_notified_at
               FROM alerts WHERE rule_id = $1 AND device_id = $2 AND series_key = $3 FOR UPDATE"#,
            rule.id,
            device_id,
            series_key
        )
        .fetch_optional(&mut **transaction)
        .await?;

        let previous_state = previous
            .as_ref()
            .map(|row| row.state.as_str())
            .unwrap_or("ok");
        let failures = previous
            .as_ref()
            .map(|row| row.consecutive_failures)
            .unwrap_or(0);
        let successes = previous
            .as_ref()
            .map(|row| row.consecutive_successes)
            .unwrap_or(0);
        let last_notified_at = previous.as_ref().and_then(|row| row.last_notified_at);
        let target_state = threshold_state(
            &rule.comparison,
            metric_value,
            rule.warning_threshold,
            rule.critical_threshold,
        );
        let progress = advance_state(
            previous_state,
            failures,
            successes,
            target_state,
            rule.consecutive_failures,
            rule.recovery_successes,
        );
        let next_state = progress.state.as_str();
        let next_failures = progress.consecutive_failures;
        let next_successes = progress.consecutive_successes;

        let alert_id = sqlx::query!(
            r#"INSERT INTO alerts (
                   rule_id, device_id, series_key, state, consecutive_failures, consecutive_successes,
                   current_value, last_evaluated_at, state_changed_at, opened_at, resolved_at
               ) VALUES (
                   $1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $8::timestamptz,
                   CASE WHEN $4 IN ('warning', 'critical') THEN $8::timestamptz ELSE NULL END,
                   CASE WHEN $4 = 'resolved' THEN $8::timestamptz ELSE NULL END
               )
               ON CONFLICT (rule_id, device_id, series_key) DO UPDATE SET
                   state = EXCLUDED.state,
                   consecutive_failures = EXCLUDED.consecutive_failures,
                   consecutive_successes = EXCLUDED.consecutive_successes,
                   current_value = EXCLUDED.current_value,
                   last_evaluated_at = EXCLUDED.last_evaluated_at,
                   state_changed_at = CASE
                       WHEN alerts.state IS DISTINCT FROM EXCLUDED.state
                       THEN EXCLUDED.state_changed_at ELSE alerts.state_changed_at END,
                   opened_at = CASE
                       WHEN EXCLUDED.state IN ('warning', 'critical')
                       THEN COALESCE(alerts.opened_at, EXCLUDED.opened_at)
                       ELSE alerts.opened_at END,
                   resolved_at = CASE
                       WHEN EXCLUDED.state = 'resolved' AND alerts.state <> 'resolved'
                       THEN EXCLUDED.resolved_at
                       WHEN EXCLUDED.state IN ('warning', 'critical') THEN NULL
                       ELSE alerts.resolved_at END
               RETURNING id"#,
            rule.id,
            device_id,
            series_key,
            next_state,
            next_failures,
            next_successes,
            metric_value,
            observed_at
        )
        .fetch_one(&mut **transaction)
        .await?
        .id;

        if previous_state != next_state {
            let event_id = sqlx::query!(
                r#"INSERT INTO alert_events
                       (alert_id, from_state, to_state, metric_value, details, occurred_at)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   RETURNING id"#,
                alert_id,
                previous_state,
                next_state,
                metric_value,
                json!({"rule_name": rule.name, "metric_name": metric_name, "series_key": series_key, "comparison": rule.comparison}),
                observed_at
            )
            .fetch_one(&mut **transaction)
            .await?
            .id;

            if should_queue_notification(
                previous_state,
                next_state,
                rule.cooldown_seconds,
                last_notified_at,
                observed_at,
            ) {
                let queued = sqlx::query!(
                    r#"INSERT INTO notification_outbox (alert_event_id, endpoint_id)
                       SELECT $1, relation.endpoint_id
                       FROM alert_rule_endpoints AS relation
                       JOIN webhook_endpoints AS endpoint ON endpoint.id = relation.endpoint_id
                       WHERE relation.rule_id = $2 AND endpoint.is_enabled = TRUE
                       ON CONFLICT (alert_event_id, endpoint_id) DO NOTHING"#,
                    event_id,
                    rule.id
                )
                .execute(&mut **transaction)
                .await?;
                if queued.rows_affected() > 0 {
                    sqlx::query!(
                        "UPDATE alerts SET last_notified_at = $2 WHERE id = $1",
                        alert_id,
                        observed_at
                    )
                    .execute(&mut **transaction)
                    .await?;
                }
            }

            events.push(json!({
                "type": "alert.transition",
                "occurred_at": observed_at,
                "data": {
                    "alert_id": alert_id,
                    "rule_id": rule.id,
                    "device_id": device_id,
                    "rule_name": rule.name,
                    "metric_name": metric_name,
                    "series_key": series_key,
                    "metric_value": metric_value,
                    "from_state": previous_state,
                    "to_state": next_state
                }
            }));
        }
    }

    Ok(events)
}

pub(crate) fn threshold_state(
    comparison: &str,
    value: f64,
    warning: Option<f64>,
    critical: Option<f64>,
) -> Option<&'static str> {
    if comparison == "unreachable" {
        return (value <= 0.0).then_some("critical");
    }

    let critical = critical?;
    let critical_breached = match comparison {
        "gt" => value > critical,
        "gte" => value >= critical,
        "lt" => value < critical,
        "lte" => value <= critical,
        _ => false,
    };
    if critical_breached {
        return Some("critical");
    }

    let warning = warning?;
    let warning_breached = match comparison {
        "gt" => value > warning,
        "gte" => value >= warning,
        "lt" => value < warning,
        "lte" => value <= warning,
        _ => false,
    };
    warning_breached.then_some("warning")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AlertProgress {
    pub(crate) state: String,
    pub(crate) consecutive_failures: i32,
    pub(crate) consecutive_successes: i32,
}

pub(crate) fn advance_state(
    previous_state: &str,
    failures: i32,
    successes: i32,
    target_state: Option<&str>,
    consecutive_failures: i32,
    recovery_successes: i32,
) -> AlertProgress {
    let (state, consecutive_failures, consecutive_successes) = match target_state {
        Some(target) => {
            let failures = failures.saturating_add(1).min(consecutive_failures);
            let state = if failures >= consecutive_failures {
                target
            } else {
                previous_state
            };
            (state, failures, 0)
        }
        None => {
            let successes = successes.saturating_add(1).min(recovery_successes);
            let state = if matches!(previous_state, "warning" | "critical")
                && successes >= recovery_successes
            {
                "resolved"
            } else {
                previous_state
            };
            (state, 0, successes)
        }
    };
    AlertProgress {
        state: state.to_owned(),
        consecutive_failures,
        consecutive_successes,
    }
}

fn should_queue_notification(
    from_state: &str,
    to_state: &str,
    cooldown_seconds: i32,
    last_notified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if to_state == "resolved" || (from_state == "warning" && to_state == "critical") {
        return true;
    }
    last_notified_at.is_none_or(|last| {
        now.signed_duration_since(last).num_seconds() >= i64::from(cooldown_seconds)
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{advance_state, should_queue_notification, threshold_state};

    #[test]
    fn classifies_numeric_warning_and_critical_breaches() {
        assert_eq!(threshold_state("gt", 5.0, Some(5.0), Some(10.0)), None);
        assert_eq!(
            threshold_state("gt", 6.0, Some(5.0), Some(10.0)),
            Some("warning")
        );
        assert_eq!(
            threshold_state("gte", 10.0, Some(5.0), Some(10.0)),
            Some("critical")
        );
        assert_eq!(
            threshold_state("lt", 4.0, Some(5.0), Some(1.0)),
            Some("warning")
        );
        assert_eq!(
            threshold_state("lte", 1.0, Some(5.0), Some(1.0)),
            Some("critical")
        );
    }

    #[test]
    fn unreachable_rules_are_critical_only_when_the_probe_is_down() {
        assert_eq!(
            threshold_state("unreachable", 0.0, None, None),
            Some("critical")
        );
        assert_eq!(threshold_state("unreachable", 1.0, None, None), None);
    }

    #[test]
    fn advances_failures_escalation_and_recovery_with_live_counters() {
        let first_failure = advance_state("ok", 0, 0, Some("warning"), 2, 2);
        assert_eq!(first_failure.state, "ok");
        assert_eq!(first_failure.consecutive_failures, 1);

        let warning = advance_state(
            &first_failure.state,
            first_failure.consecutive_failures,
            first_failure.consecutive_successes,
            Some("warning"),
            2,
            2,
        );
        assert_eq!(warning.state, "warning");
        assert_eq!(warning.consecutive_failures, 2);

        let critical = advance_state(&warning.state, 2, 0, Some("critical"), 2, 2);
        assert_eq!(critical.state, "critical");

        let partial_recovery = advance_state(&critical.state, 2, 0, None, 2, 2);
        assert_eq!(partial_recovery.state, "critical");
        assert_eq!(partial_recovery.consecutive_successes, 1);

        let recovery = advance_state(
            &partial_recovery.state,
            partial_recovery.consecutive_failures,
            partial_recovery.consecutive_successes,
            None,
            2,
            2,
        );
        assert_eq!(recovery.state, "resolved");
        assert_eq!(recovery.consecutive_successes, 2);
    }

    #[test]
    fn cooldown_suppresses_repeat_open_notifications_but_not_escalation_or_recovery() {
        let now = Utc
            .timestamp_opt(1_000, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let last = now - Duration::seconds(10);
        assert!(!should_queue_notification(
            "resolved",
            "warning",
            300,
            Some(last),
            now
        ));
        assert!(should_queue_notification(
            "warning",
            "critical",
            300,
            Some(last),
            now
        ));
        assert!(should_queue_notification(
            "critical",
            "resolved",
            300,
            Some(last),
            now
        ));
        assert!(should_queue_notification(
            "resolved",
            "warning",
            300,
            Some(last),
            last + Duration::seconds(300)
        ));
    }
}
