use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use reqwest::{Client, redirect::Policy};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use tokio::{net::lookup_host, time};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    state::AppState,
    webhook_providers::{
        GenericWebhookPayload, WebhookConfig, generic_payload, provider_payload, request_url,
        validate_provider_url,
    },
};

const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct ResolvedTarget {
    url: reqwest::Url,
    host: String,
    addresses: Vec<SocketAddr>,
}

#[derive(Debug, FromRow)]
struct DeliveryJob {
    outbox_id: Uuid,
    endpoint_id: Uuid,
    attempt_count: i32,
    provider: String,
    config_ciphertext: Vec<u8>,
    alert_event_id: Uuid,
    alert_id: Uuid,
    rule_id: Uuid,
    device_id: Uuid,
    rule_name: String,
    from_state: String,
    to_state: String,
    metric_value: Option<f64>,
    details: JsonValue,
    occurred_at: DateTime<Utc>,
}

pub async fn run(state: AppState, shutdown: CancellationToken) {
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match claim_one(&state).await {
            Ok(Some(job)) => {
                let outcome = time::timeout(DELIVERY_TIMEOUT, deliver(&state, &job)).await;
                match outcome {
                    Ok(Ok(())) => {
                        if let Err(error) = mark_delivered(&state, job.outbox_id).await {
                            tracing::error!(outbox_id = %job.outbox_id, error = %error, "failed to mark webhook delivery complete");
                        }
                    }
                    Ok(Err(reason)) => retry_later(&state, &job, &reason).await,
                    Err(_) => retry_later(&state, &job, "delivery timed out").await,
                }
            }
            Ok(None) => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = time::sleep(IDLE_POLL_INTERVAL) => {}
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "webhook outbox claim failed");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = time::sleep(IDLE_POLL_INTERVAL) => {}
                }
            }
        }
    }
    tracing::info!("webhook dispatcher stopped");
}

async fn claim_one(state: &AppState) -> Result<Option<DeliveryJob>, sqlx::Error> {
    sqlx::query_as!(
        DeliveryJob,
        r#"WITH candidate AS (
               SELECT outbox.id
               FROM notification_outbox AS outbox
               JOIN webhook_endpoints AS endpoint ON endpoint.id = outbox.endpoint_id
               WHERE endpoint.is_enabled
                 AND ((outbox.status IN ('pending', 'failed') AND outbox.next_attempt_at <= now())
                      OR (outbox.status = 'delivering' AND outbox.updated_at < now() - interval '5 minutes'))
               ORDER BY outbox.next_attempt_at, outbox.created_at
               FOR UPDATE SKIP LOCKED
               LIMIT 1
           ), claimed AS (
               UPDATE notification_outbox AS outbox
               SET status = 'delivering', attempt_count = outbox.attempt_count + 1,
                   last_error = NULL, updated_at = now()
               FROM candidate
               WHERE outbox.id = candidate.id
               RETURNING outbox.id, outbox.alert_event_id, outbox.endpoint_id, outbox.attempt_count
           )
           SELECT claimed.id AS outbox_id, claimed.endpoint_id, claimed.attempt_count,
                  endpoint.provider, endpoint.config_ciphertext,
                  event.id AS alert_event_id, event.alert_id, alert.rule_id, alert.device_id,
                  rule.name AS rule_name, event.from_state, event.to_state, event.metric_value,
                  event.details AS "details: JsonValue", event.occurred_at
           FROM claimed
           JOIN webhook_endpoints AS endpoint ON endpoint.id = claimed.endpoint_id
           JOIN alert_events AS event ON event.id = claimed.alert_event_id
           JOIN alerts AS alert ON alert.id = event.alert_id
           JOIN alert_rules AS rule ON rule.id = alert.rule_id"#
    )
    .fetch_optional(&state.db)
    .await
}

async fn deliver(state: &AppState, job: &DeliveryJob) -> Result<(), &'static str> {
    let associated_data = format!("webhook:{}:config", job.endpoint_id);
    let plaintext = state
        .credential_cipher
        .decrypt(associated_data.as_bytes(), &job.config_ciphertext)
        .map_err(|_| "webhook config decryption failed")?;
    let credentials: WebhookConfig =
        serde_json::from_slice(&plaintext).map_err(|_| "webhook config is invalid")?;
    let request_url =
        request_url(&job.provider, &credentials).map_err(|_| "webhook config is invalid")?;
    validate_provider_url(&job.provider, &request_url)
        .map_err(|_| "webhook target is not permitted")?;
    let target = resolve_public_target(&request_url)
        .await
        .map_err(|_| "webhook target is not permitted")?;

    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(&target.host, &target.addresses)
        .build()
        .map_err(|_| "HTTP client initialization failed")?;
    let payload = if job.provider == "generic" {
        generic_payload(GenericWebhookPayload {
            event_id: job.alert_event_id,
            alert_id: job.alert_id,
            rule_id: job.rule_id,
            device_id: job.device_id,
            rule_name: &job.rule_name,
            from_state: &job.from_state,
            to_state: &job.to_state,
            metric_value: job.metric_value,
            details: job.details.clone(),
            occurred_at: job.occurred_at,
        })
    } else {
        provider_payload(
            &job.provider,
            credentials.chat_id.as_deref(),
            job.alert_event_id,
            job.device_id,
            &job.rule_name,
            job.details.get("metric_name").and_then(JsonValue::as_str),
            job.details.get("series_key").and_then(JsonValue::as_str),
            &job.from_state,
            &job.to_state,
            job.metric_value,
        )?
    };
    let mut request = client.post(target.url).json(&payload);
    if job.provider == "generic" {
        if let Some(token) = credentials.bearer_token {
            let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| "webhook bearer token is invalid")?;
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
    }
    let response = request.send().await.map_err(|_| "webhook request failed")?;
    let status = response.status();
    let body = if status.is_success() && matches!(job.provider.as_str(), "telegram" | "slack") {
        Some(read_limited_body(response).await?)
    } else {
        None
    };
    validate_provider_response(&job.provider, status, body.as_deref())
}

fn validate_provider_response(
    provider: &str,
    status: reqwest::StatusCode,
    body: Option<&[u8]>,
) -> Result<(), &'static str> {
    if !status.is_success() {
        return Err("webhook returned a non-success status");
    }
    match provider {
        "telegram" => {
            let body = body.ok_or("Telegram API response was missing")?;
            let result: TelegramResponse =
                serde_json::from_slice(body).map_err(|_| "Telegram API response was invalid")?;
            if !result.ok {
                return Err("Telegram API rejected the notification");
            }
        }
        "slack" => {
            let body = body.ok_or("Slack incoming webhook response was missing")?;
            if std::str::from_utf8(body).map(str::trim).ok() != Some("ok") {
                return Err("Slack incoming webhook rejected the notification");
            }
        }
        "generic" | "discord" => {}
        _ => return Err("unsupported webhook provider"),
    }
    Ok(())
}

#[derive(Deserialize)]
struct TelegramResponse {
    ok: bool,
}

async fn read_limited_body(response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "webhook response body could not be read")?;
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            return Err("webhook response body exceeded the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub async fn resolve_public_target(value: &str) -> anyhow::Result<ResolvedTarget> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        anyhow::bail!(
            "webhook URL must be HTTPS on port 443 without user information or a fragment"
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("webhook URL has no host"))?
        .to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        anyhow::bail!("webhook hostname is not permitted");
    }

    let mut addresses = lookup_host((host.as_str(), 443)).await?.collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses.iter().any(|address| !is_public_ip(address.ip()))
    {
        anyhow::bail!("webhook hostname did not resolve exclusively to public addresses");
    }
    Ok(ResolvedTarget {
        url,
        host,
        addresses,
    })
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => {
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
            {
                return false;
            }
            let octets = ip.octets();
            if octets[..10] == [0; 10] && octets[10..12] == [0xff, 0xff] {
                let mapped =
                    std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_public_ipv4(mapped);
            }
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000
                && segments[0] != 0x2002
                && !(segments[0] == 0x2001
                    && (segments[1] == 0x0db8
                        || segments[1] == 0x0000
                        || (segments[1] & 0xfff0) == 0x0020))
        }
    }
}

fn is_public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    let [first, second, third, _] = octets;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || first == 0
        || first >= 224
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 192 && second == 88 && third == 99)
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113))
}

async fn mark_delivered(state: &AppState, outbox_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"UPDATE notification_outbox
           SET status = 'delivered', delivered_at = now(), last_error = NULL, updated_at = now()
           WHERE id = $1 AND status = 'delivering'"#,
        outbox_id
    )
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn retry_later(state: &AppState, job: &DeliveryJob, reason: &str) {
    let exponent = job.attempt_count.clamp(0, 10) as u32;
    let delay_seconds = 2_i64.saturating_pow(exponent).min(3_600) as i32;
    if let Err(error) = sqlx::query!(
        r#"UPDATE notification_outbox
           SET status = 'failed', next_attempt_at = now() + ($2::int * interval '1 second'),
               last_error = $3, updated_at = now()
           WHERE id = $1 AND status = 'delivering'"#,
        job.outbox_id,
        delay_seconds,
        reason
    )
    .execute(&state.db)
    .await
    {
        tracing::error!(outbox_id = %job.outbox_id, error = %error, "failed to schedule webhook retry");
    } else {
        tracing::warn!(outbox_id = %job.outbox_id, attempt = job.attempt_count, "webhook delivery failed; retry scheduled");
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{is_public_ip, validate_provider_response};

    #[test]
    fn rejects_private_and_special_use_addresses() -> anyhow::Result<()> {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.10",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            let ip = address.parse::<IpAddr>()?;
            assert!(
                !is_public_ip(ip),
                "{address} should not be considered public"
            );
        }
        Ok(())
    }

    #[test]
    fn accepts_representative_public_addresses() -> anyhow::Result<()> {
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            let ip = address.parse::<IpAddr>()?;
            assert!(is_public_ip(ip), "{address} should be considered public");
        }
        Ok(())
    }

    #[test]
    fn validates_provider_acknowledgements() {
        let ok = reqwest::StatusCode::OK;
        assert!(validate_provider_response("telegram", ok, Some(br#"{"ok":true}"#)).is_ok());
        assert!(validate_provider_response("telegram", ok, Some(br#"{"ok":false}"#)).is_err());
        assert!(validate_provider_response("slack", ok, Some(b"ok\n")).is_ok());
        assert!(validate_provider_response("slack", ok, Some(b"invalid_payload")).is_err());
        assert!(
            validate_provider_response("discord", reqwest::StatusCode::NO_CONTENT, None).is_ok()
        );
        assert!(validate_provider_response("generic", reqwest::StatusCode::ACCEPTED, None).is_ok());
        assert!(
            validate_provider_response("discord", reqwest::StatusCode::TOO_MANY_REQUESTS, None)
                .is_err()
        );
        assert!(validate_provider_response("unsupported", ok, None).is_err());
    }
}
