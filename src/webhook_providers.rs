use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub(crate) struct WebhookConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bearer_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bot_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) chat_id: Option<String>,
}

pub(crate) fn telegram_api_url(bot_token: &str) -> String {
    format!("https://api.telegram.org/bot{bot_token}/sendMessage")
}

pub(crate) fn request_url(provider: &str, config: &WebhookConfig) -> Result<String, &'static str> {
    match provider {
        "generic" | "slack" | "discord" => config.url.clone().ok_or("webhook URL is missing"),
        "telegram" => {
            let bot_token = config
                .bot_token
                .as_deref()
                .ok_or("Telegram bot token is missing")?;
            let chat_id = config
                .chat_id
                .as_deref()
                .ok_or("Telegram chat ID is missing")?;
            if !is_telegram_bot_token(bot_token) || !is_telegram_chat_id(chat_id) {
                return Err("Telegram configuration is invalid");
            }
            Ok(telegram_api_url(bot_token))
        }
        _ => Err("unsupported webhook provider"),
    }
}

pub(crate) fn validate_provider_url(provider: &str, value: &str) -> Result<(), &'static str> {
    let url = reqwest::Url::parse(value).map_err(|_| "webhook URL is invalid")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (provider != "generic" && url.query().is_some())
    {
        return Err("provider webhook URL must use HTTPS on port 443 without user info");
    }

    let host = url.host_str().ok_or("webhook URL has no host")?;
    let parts = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .ok_or("webhook URL path is invalid")?;

    let accepted = match provider {
        "generic" => true,
        "telegram" => {
            host == "api.telegram.org"
                && parts.len() == 2
                && parts[0]
                    .strip_prefix("bot")
                    .is_some_and(is_telegram_bot_token)
                && parts[1] == "sendMessage"
        }
        "slack" => {
            host == "hooks.slack.com"
                && parts.len() == 4
                && parts[0] == "services"
                && parts[1..].iter().all(|part| valid_path_token(part, 128))
        }
        "discord" => {
            host == "discord.com"
                && parts.len() == 4
                && parts[0] == "api"
                && parts[1] == "webhooks"
                && !parts[2].is_empty()
                && parts[2].len() <= 24
                && parts[2].bytes().all(|byte| byte.is_ascii_digit())
                && valid_path_token(parts[3], 256)
        }
        _ => false,
    };
    if accepted {
        Ok(())
    } else {
        Err("webhook URL does not match the selected provider")
    }
}

pub(crate) fn provider_payload(
    provider: &str,
    chat_id: Option<&str>,
    event_id: Uuid,
    device_id: Uuid,
    rule_name: &str,
    metric_name: Option<&str>,
    series_key: Option<&str>,
    from_state: &str,
    to_state: &str,
    metric_value: Option<f64>,
) -> Result<Value, &'static str> {
    let text = alert_message(
        event_id,
        device_id,
        rule_name,
        metric_name,
        series_key,
        from_state,
        to_state,
        metric_value,
    );
    match provider {
        "telegram" => Ok(json!({
            "chat_id": chat_id.ok_or("Telegram chat ID is missing")?,
            "text": text
        })),
        "slack" => Ok(json!({"text": text})),
        "discord" => Ok(json!({
            "content": text,
            "allowed_mentions": {"parse": []}
        })),
        _ => Err("unsupported provider payload"),
    }
}

pub(crate) struct GenericWebhookPayload<'a> {
    pub(crate) event_id: Uuid,
    pub(crate) alert_id: Uuid,
    pub(crate) rule_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) rule_name: &'a str,
    pub(crate) from_state: &'a str,
    pub(crate) to_state: &'a str,
    pub(crate) metric_value: Option<f64>,
    pub(crate) details: Value,
    pub(crate) occurred_at: DateTime<Utc>,
}

pub(crate) fn generic_payload(event: GenericWebhookPayload<'_>) -> Value {
    json!({
        "id": event.event_id,
        "alert_id": event.alert_id,
        "rule_id": event.rule_id,
        "device_id": event.device_id,
        "rule_name": event.rule_name,
        "from_state": event.from_state,
        "to_state": event.to_state,
        "metric_value": event.metric_value,
        "details": event.details,
        "occurred_at": event.occurred_at
    })
}

fn alert_message(
    event_id: Uuid,
    device_id: Uuid,
    rule_name: &str,
    metric_name: Option<&str>,
    series_key: Option<&str>,
    from_state: &str,
    to_state: &str,
    metric_value: Option<f64>,
) -> String {
    let metric_name = metric_name.unwrap_or("metric");
    let metric_value = metric_value
        .filter(|value| value.is_finite())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    let series = series_key
        .filter(|key| !key.is_empty())
        .map(|key| format!("\nSeries: {}", safe_display(key)))
        .unwrap_or_default();
    format!(
        "NMS alert {event_id}\n{}: {} → {}\nDevice: {device_id}\n{}: {metric_value}{series}",
        safe_display(rule_name),
        safe_display(from_state),
        safe_display(to_state),
        safe_display(metric_name),
    )
}

fn safe_display(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '@' => '＠',
            '<' => '‹',
            '>' => '›',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect()
}

pub(crate) fn is_telegram_bot_token(token: &str) -> bool {
    let Some((bot_id, secret)) = token.split_once(':') else {
        return false;
    };
    !bot_id.is_empty()
        && bot_id.len() <= 20
        && bot_id.bytes().all(|byte| byte.is_ascii_digit())
        && !secret.is_empty()
        && secret.len() <= 200
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn is_telegram_chat_id(chat_id: &str) -> bool {
    if chat_id.parse::<i64>().is_ok() {
        return true;
    }
    let Some(username) = chat_id.strip_prefix('@') else {
        return false;
    };
    (5..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_path_token(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        GenericWebhookPayload, WebhookConfig, generic_payload, is_telegram_bot_token,
        is_telegram_chat_id, provider_payload, request_url, telegram_api_url,
        validate_provider_url,
    };

    #[test]
    fn validates_provider_hosts_and_paths() {
        assert!(validate_provider_url("telegram", &telegram_api_url("123456:Abc_DEF-1")).is_ok());
        assert!(
            validate_provider_url("slack", "https://hooks.slack.com/services/T123/B123/secret")
                .is_ok()
        );
        assert!(
            validate_provider_url(
                "discord",
                "https://discord.com/api/webhooks/123456789012345678/token.secret"
            )
            .is_ok()
        );
        assert!(
            validate_provider_url(
                "slack",
                "https://hooks.slack.com.attacker.invalid/services/T123/B123/secret"
            )
            .is_err()
        );
        assert!(
            validate_provider_url(
                "discord",
                "https://discord.com.attacker.invalid/api/webhooks/123/token"
            )
            .is_err()
        );
        assert!(
            validate_provider_url(
                "discord",
                "https://discord.com/api/webhooks/123/token?redirect=https://example.com"
            )
            .is_err()
        );
        assert!(validate_provider_url("generic", "https://example.com/hook?key=value").is_ok());
    }

    #[test]
    fn validates_telegram_credentials() {
        assert!(is_telegram_bot_token("123456:Abc_DEF-1"));
        assert!(!is_telegram_bot_token("123456:bad:token"));
        assert!(is_telegram_chat_id("-1001234567890"));
        assert!(is_telegram_chat_id("@channel_name"));
        assert!(!is_telegram_chat_id("@x"));
    }

    #[test]
    fn builds_expected_provider_payloads_without_mentions() -> anyhow::Result<()> {
        let event_id = Uuid::parse_str("9ff5ab5c-8fd2-4988-8c87-2a3462b4021c")?;
        let device_id = Uuid::parse_str("c803a1e4-9d8b-4a7b-b15c-f622cd9d36bb")?;
        let telegram = provider_payload(
            "telegram",
            Some("-1001234567890"),
            event_id,
            device_id,
            "@everyone <edge>",
            Some("icmp_reachable"),
            Some("port=443"),
            "ok",
            "critical",
            Some(0.0),
        )
        .map_err(anyhow::Error::msg)?;
        assert_eq!(telegram["chat_id"], "-1001234567890");
        assert!(
            telegram["text"]
                .as_str()
                .is_some_and(|text| text.contains("Series: port=443"))
        );
        assert!(
            telegram["text"]
                .as_str()
                .is_some_and(|text| text.contains("＠everyone ‹edge›"))
        );

        let slack = provider_payload(
            "slack",
            None,
            event_id,
            device_id,
            "edge",
            Some("icmp_reachable"),
            None,
            "ok",
            "critical",
            Some(0.0),
        )
        .map_err(anyhow::Error::msg)?;
        assert!(slack["text"].as_str().is_some());

        let discord = provider_payload(
            "discord",
            None,
            event_id,
            device_id,
            "edge",
            Some("icmp_reachable"),
            None,
            "ok",
            "critical",
            Some(0.0),
        )
        .map_err(anyhow::Error::msg)?;
        assert_eq!(discord["allowed_mentions"]["parse"], serde_json::json!([]));
        assert!(discord["content"].as_str().is_some());
        Ok(())
    }

    #[test]
    fn builds_generic_payload_with_live_dispatcher_fields() -> anyhow::Result<()> {
        let event_id = Uuid::parse_str("9ff5ab5c-8fd2-4988-8c87-2a3462b4021c")?;
        let alert_id = Uuid::parse_str("c803a1e4-9d8b-4a7b-b15c-f622cd9d36bb")?;
        let rule_id = Uuid::parse_str("c4b81678-9270-49e0-9ed4-6beab91e860e")?;
        let device_id = Uuid::parse_str("efb3c6b8-50ef-4c79-a340-192851d2c6e4")?;
        let occurred_at = chrono::DateTime::parse_from_rfc3339("2026-11-24T05:00:00Z")?
            .with_timezone(&chrono::Utc);
        let payload = generic_payload(GenericWebhookPayload {
            event_id,
            alert_id,
            rule_id,
            device_id,
            rule_name: "CPU high",
            from_state: "ok",
            to_state: "warning",
            metric_value: Some(91.0),
            details: json!({"metric_name": "snmp_cpu_percent", "series_key": ""}),
            occurred_at,
        });
        assert_eq!(payload["id"], event_id.to_string());
        assert_eq!(payload["alert_id"], alert_id.to_string());
        assert_eq!(payload["rule_id"], rule_id.to_string());
        assert_eq!(payload["device_id"], device_id.to_string());
        assert_eq!(payload["to_state"], "warning");
        assert_eq!(payload["details"]["metric_name"], "snmp_cpu_percent");
        Ok(())
    }

    #[test]
    fn reads_legacy_generic_configuration_and_builds_telegram_target() -> anyhow::Result<()> {
        let legacy: WebhookConfig =
            serde_json::from_str(r#"{"url":"https://example.com/hook","bearer_token":null}"#)?;
        assert_eq!(legacy.url.as_deref(), Some("https://example.com/hook"));

        let telegram = WebhookConfig {
            url: None,
            bearer_token: None,
            bot_token: Some("123456:Abc_DEF-1".to_owned()),
            chat_id: Some("-1001234567890".to_owned()),
        };
        assert_eq!(
            request_url("telegram", &telegram).map_err(anyhow::Error::msg)?,
            "https://api.telegram.org/bot123456:Abc_DEF-1/sendMessage"
        );
        Ok(())
    }
}
