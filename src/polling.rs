use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use async_snmp::{
    Auth, AuthProtocol, Client, PrivProtocol, Retry, UsmConfig, Value, VarBind, WalkOptions, oid,
};
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use serde_json::{Value as JsonValue, json};
use sqlx::FromRow;
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{self, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{alerting, crypto::SecretCipher, state::AppState};

const SCHEDULER_INTERVAL: Duration = Duration::from_secs(1);
const MAX_WALK_RESULTS: usize = 4096;
static NEXT_PING_IDENTIFIER: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, FromRow)]
struct PollDevice {
    id: Uuid,
    ip_address: String,
    probe_timeout_ms: i32,
    tcp_probe_ports: Vec<i32>,
    snmp_version: Option<String>,
    snmp_port: i32,
    snmp_v2c_community_ciphertext: Option<Vec<u8>>,
    snmp_v3_username: Option<String>,
    snmp_v3_auth_protocol: Option<String>,
    snmp_v3_auth_secret_ciphertext: Option<Vec<u8>>,
    snmp_v3_priv_protocol: Option<String>,
    snmp_v3_priv_secret_ciphertext: Option<Vec<u8>>,
    ssh_port: i32,
    ssh_username: Option<String>,
    ssh_private_key_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PollMetric {
    name: String,
    series_key: String,
    value: f64,
    unit: String,
    labels: JsonValue,
}

#[derive(Debug, Clone)]
struct CounterSample {
    if_index: i32,
    direction: &'static str,
    value: u64,
    bits: i16,
    if_name: Option<String>,
    if_descr: Option<String>,
    discontinuity_ticks: Option<u32>,
}

#[derive(Debug, FromRow)]
struct CounterBaseline {
    counter_value: String,
    counter_bits: i16,
    observed_at: DateTime<Utc>,
    sys_uptime_ticks: Option<i64>,
    discontinuity_ticks: Option<i64>,
}

#[derive(Debug, Default)]
struct SnmpData {
    sys_name: Option<String>,
    sys_descr: Option<String>,
    uptime_seconds: Option<f64>,
    uptime_ticks: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceStatus {
    Up,
    Degraded,
    Down,
}

impl DeviceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }
}

pub async fn run(state: AppState, shutdown: CancellationToken) {
    let mut interval = time::interval(SCHEDULER_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut tasks = JoinSet::new();
    let mut in_flight = HashSet::new();

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        schedule_due_devices(&state, &mut tasks, &mut in_flight).await;

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {},
            joined = tasks.join_next(), if !tasks.is_empty() => {
                handle_joined(joined, &mut in_flight);
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        handle_joined(Some(joined), &mut in_flight);
    }
    tracing::info!("polling worker stopped after draining active probes");
}

fn handle_joined(
    joined: Option<Result<(Uuid, Result<(), sqlx::Error>), tokio::task::JoinError>>,
    in_flight: &mut HashSet<Uuid>,
) {
    match joined {
        Some(Ok((device_id, Ok(())))) => {
            in_flight.remove(&device_id);
        }
        Some(Ok((device_id, Err(error)))) => {
            in_flight.remove(&device_id);
            tracing::error!(device_id = %device_id, error = %error, "failed to persist device poll");
        }
        Some(Err(error)) => {
            tracing::error!(error = %error, "device polling task failed unexpectedly");
        }
        None => {}
    }
}

async fn schedule_due_devices(
    state: &AppState,
    tasks: &mut JoinSet<(Uuid, Result<(), sqlx::Error>)>,
    in_flight: &mut HashSet<Uuid>,
) {
    let room = state.max_probe_concurrency.saturating_sub(tasks.len());
    if room == 0 {
        return;
    }

    let permits = reserve_available_permits(&state.probe_semaphore, room);
    if permits.is_empty() {
        return;
    }

    let excluded_ids = in_flight.iter().copied().collect::<Vec<_>>();
    let limit = permits.len() as i64;
    let devices = match sqlx::query_as!(
        PollDevice,
        r#"SELECT
            id,
            host(ip_address) AS "ip_address!",
            probe_timeout_ms,
            tcp_probe_ports AS "tcp_probe_ports!",
            snmp_version,
            snmp_port,
            snmp_v2c_community_ciphertext,
            snmp_v3_username,
            snmp_v3_auth_protocol,
            snmp_v3_auth_secret_ciphertext,
            snmp_v3_priv_protocol,
            snmp_v3_priv_secret_ciphertext,
            ssh_port,
            ssh_username,
            ssh_private_key_ciphertext
         FROM devices
         WHERE is_enabled = TRUE
           AND deleted_at IS NULL
           AND (last_checked_at IS NULL OR
                last_checked_at <= now() - poll_interval_seconds * interval '1 second')
           AND id <> ALL($1::uuid[])
         ORDER BY last_checked_at NULLS FIRST, ip_address
         LIMIT $2"#,
        &excluded_ids,
        limit
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(devices) => devices,
        Err(error) => {
            tracing::error!(error = %error, "poll scheduler query failed");
            return;
        }
    };

    for (device, permit) in devices.into_iter().zip(permits) {
        let device_id = device.id;
        in_flight.insert(device_id);
        let state = state.clone();
        tasks.spawn(async move {
            let poll = AssertUnwindSafe(poll_device(&state, device, permit))
                .catch_unwind()
                .await;
            let result = match poll {
                Ok(result) => result,
                Err(_) => {
                    tracing::error!(device_id = %device_id, "device polling task panicked");
                    Ok(())
                }
            };
            (device_id, result)
        });
    }
}

fn reserve_available_permits(
    semaphore: &Arc<Semaphore>,
    limit: usize,
) -> Vec<OwnedSemaphorePermit> {
    let mut permits = Vec::with_capacity(limit.min(semaphore.available_permits()));
    for _ in 0..limit {
        match Arc::clone(semaphore).try_acquire_owned() {
            Ok(permit) => permits.push(permit),
            Err(_) => break,
        }
    }
    permits
}

async fn poll_device(
    state: &AppState,
    device: PollDevice,
    _permit: OwnedSemaphorePermit,
) -> Result<(), sqlx::Error> {
    let probe_timeout = Duration::from_millis(device.probe_timeout_ms as u64);
    let address = match device.ip_address.parse::<IpAddr>() {
        Ok(address) => address,
        Err(error) => {
            tracing::error!(device_id = %device.id, error = %error, "database returned an invalid device address");
            return Ok(());
        }
    };

    let mut probe_results = Vec::with_capacity(4 + device.tcp_probe_ports.len());
    let mut metrics = Vec::with_capacity(16 + device.tcp_probe_ports.len() * 2);
    let mut snmp_data = None;
    let mut counter_samples = Vec::new();
    let mut uptime_ticks = None;
    let mut tcp_results = HashMap::<u16, (bool, Option<f64>)>::new();

    let icmp_result = time::timeout(probe_timeout, probe_icmp(address, probe_timeout)).await;
    let icmp_ok = matches!(icmp_result, Ok(Ok(_)));
    probe_results.push(icmp_ok);
    metrics.push(probe_metric(
        "icmp_reachable",
        if icmp_ok { 1.0 } else { 0.0 },
        None,
        "icmp",
    ));
    if let Ok(Ok(round_trip)) = icmp_result {
        metrics.push(probe_metric(
            "icmp_latency_ms",
            round_trip.as_secs_f64() * 1000.0,
            Some("ms"),
            "icmp",
        ));
    }

    if device.ssh_username.is_some() && device.ssh_private_key_ciphertext.is_some() {
        let result = probe_tcp_port(address, device.ssh_port as u16, probe_timeout).await;
        tcp_results.insert(device.ssh_port as u16, result);
        let (tcp_ok, latency_ms) = result;
        probe_results.push(tcp_ok);
        metrics.push(probe_metric(
            "tcp_reachable",
            if tcp_ok { 1.0 } else { 0.0 },
            None,
            "tcp",
        ));
        if let Some(latency_ms) = latency_ms {
            metrics.push(probe_metric(
                "tcp_connect_latency_ms",
                latency_ms,
                Some("ms"),
                "tcp",
            ));
        }
    }

    for configured_port in &device.tcp_probe_ports {
        let port = *configured_port as u16;
        let (tcp_ok, latency_ms) = match tcp_results.get(&port).copied() {
            Some(result) => result,
            None => probe_tcp_port(address, port, probe_timeout).await,
        };
        probe_results.push(tcp_ok);
        let series_key = format!("port={port}");
        let labels = json!({"probe": "tcp", "port": port, "kind": "configured"});
        metrics.push(metric_with_series(
            "tcp_reachable",
            if tcp_ok { 1.0 } else { 0.0 },
            None,
            "tcp",
            series_key.clone(),
            labels.clone(),
        ));
        if let Some(latency_ms) = latency_ms {
            metrics.push(metric_with_series(
                "tcp_connect_latency_ms",
                latency_ms,
                Some("ms"),
                "tcp",
                series_key,
                labels,
            ));
        }
    }

    if device.snmp_version.is_some() {
        match time::timeout(probe_timeout, probe_snmp_base(state, &device)).await {
            Ok(Ok((client, data))) => {
                probe_results.push(true);
                metrics.push(probe_metric("snmp_reachable", 1.0, None, "snmp"));
                uptime_ticks = data.uptime_ticks;
                if let Some(uptime) = data.uptime_seconds {
                    metrics.push(probe_metric(
                        "sys_uptime_seconds",
                        uptime,
                        Some("seconds"),
                        "snmp",
                    ));
                }
                match time::timeout(probe_timeout, collect_optional_snmp(&client)).await {
                    Ok((extra_metrics, samples)) => {
                        metrics.extend(extra_metrics);
                        counter_samples = samples;
                    }
                    Err(_) => {
                        tracing::debug!(device_id = %device.id, "optional SNMP metric walks timed out")
                    }
                }
                snmp_data = Some(data);
            }
            Ok(Err(_)) | Err(_) => {
                probe_results.push(false);
                metrics.push(probe_metric("snmp_reachable", 0.0, None, "snmp"));
            }
        }
    }

    let status = derive_status(&probe_results);
    let (sys_name, sys_descr) = snmp_data
        .map(|data| (data.sys_name, data.sys_descr))
        .unwrap_or((None, None));
    let events = persist_poll(
        state,
        device.id,
        status,
        Utc::now(),
        sys_name,
        sys_descr,
        uptime_ticks,
        &metrics,
        &counter_samples,
    )
    .await?;
    for event in events {
        let _ = state.events.send(event);
    }
    Ok(())
}

fn probe_metric(name: &str, value: f64, unit: Option<&str>, probe: &str) -> PollMetric {
    metric_with_series(
        name,
        value,
        unit,
        probe,
        String::new(),
        json!({"probe": probe}),
    )
}

fn metric_with_series(
    name: &str,
    value: f64,
    unit: Option<&str>,
    probe: &str,
    series_key: String,
    labels: JsonValue,
) -> PollMetric {
    PollMetric {
        name: name.to_owned(),
        series_key,
        value,
        unit: unit.unwrap_or("1").to_owned(),
        labels: if labels.is_null() {
            json!({"probe": probe})
        } else {
            labels
        },
    }
}

async fn probe_tcp_port(address: IpAddr, port: u16, timeout: Duration) -> (bool, Option<f64>) {
    let started = Instant::now();
    match time::timeout(timeout, TcpStream::connect(SocketAddr::new(address, port))).await {
        Ok(Ok(_stream)) => (true, Some(started.elapsed().as_secs_f64() * 1000.0)),
        Ok(Err(_)) | Err(_) => (false, None),
    }
}

fn derive_status(probes: &[bool]) -> DeviceStatus {
    let successful = probes.iter().filter(|result| **result).count();
    if successful == 0 {
        DeviceStatus::Down
    } else if successful == probes.len() {
        DeviceStatus::Up
    } else {
        DeviceStatus::Degraded
    }
}

async fn probe_icmp(address: IpAddr, timeout: Duration) -> anyhow::Result<Duration> {
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};

    let kind = match address {
        IpAddr::V4(_) => ICMP::V4,
        IpAddr::V6(_) => ICMP::V6,
    };
    let config = Config::builder().kind(kind).build();
    let client = Client::new(&config)?;
    let identifier = PingIdentifier(NEXT_PING_IDENTIFIER.fetch_add(1, Ordering::Relaxed));
    let mut pinger = client.pinger(address, identifier).await;
    pinger.timeout(timeout);
    let (_, round_trip) = pinger.ping(PingSequence(0), b"rust-nms-poll").await?;
    Ok(round_trip)
}

async fn probe_snmp_base(
    state: &AppState,
    device: &PollDevice,
) -> anyhow::Result<(Client, SnmpData)> {
    let auth = build_snmp_auth(&state.credential_cipher, device)?;
    let timeout = Duration::from_millis(device.probe_timeout_ms as u64);
    let target = (device.ip_address.as_str(), device.snmp_port as u16);
    let client = Client::builder(target, auth)
        .request_timeout(timeout)
        .retry(Retry::none())
        .connect()
        .await?;
    let response = client.get_many(&system_oids()).await?;
    Ok((client, parse_snmp_bindings(&response.varbinds)))
}

fn build_snmp_auth(cipher: &SecretCipher, device: &PollDevice) -> anyhow::Result<Auth> {
    match device.snmp_version.as_deref() {
        Some("v2c") => {
            let ciphertext = device
                .snmp_v2c_community_ciphertext
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SNMP v2c community ciphertext is missing"))?;
            let aad = format!("device:{}:snmp_v2c_community", device.id);
            let community = cipher.decrypt_string(aad.as_bytes(), ciphertext)?;
            Ok(Auth::v2c(community))
        }
        Some("v3") => {
            let username = device
                .snmp_v3_username
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SNMP v3 username is missing"))?;
            let auth_protocol = device
                .snmp_v3_auth_protocol
                .as_deref()
                .and_then(parse_auth_protocol)
                .ok_or_else(|| anyhow::anyhow!("SNMP v3 auth protocol is unsupported"))?;
            let auth_ciphertext = device
                .snmp_v3_auth_secret_ciphertext
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("SNMP v3 auth ciphertext is missing"))?;
            let auth_aad = format!("device:{}:snmp_v3_auth_secret", device.id);
            let auth_secret = cipher.decrypt_string(auth_aad.as_bytes(), auth_ciphertext)?;
            let config = match device.snmp_v3_priv_protocol.as_deref() {
                Some(protocol_name) => {
                    let protocol = parse_priv_protocol(protocol_name).ok_or_else(|| {
                        anyhow::anyhow!("SNMP v3 privacy protocol is unsupported")
                    })?;
                    let priv_ciphertext = device
                        .snmp_v3_priv_secret_ciphertext
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("SNMP v3 privacy ciphertext is missing"))?;
                    let priv_aad = format!("device:{}:snmp_v3_priv_secret", device.id);
                    let priv_secret =
                        cipher.decrypt_string(priv_aad.as_bytes(), priv_ciphertext)?;
                    UsmConfig::new(username.to_owned())
                        .auth_priv(auth_protocol, auth_secret, protocol, priv_secret)
                        .map_err(|_| {
                            anyhow::anyhow!("SNMP v3 credential configuration is invalid")
                        })?
                }
                None => UsmConfig::new(username.to_owned())
                    .auth(auth_protocol, auth_secret)
                    .map_err(|_| anyhow::anyhow!("SNMP v3 credential configuration is invalid"))?,
            };
            Ok(Auth::from(config))
        }
        Some(_) => anyhow::bail!("stored SNMP version is unsupported"),
        None => anyhow::bail!("SNMP is not configured for this device"),
    }
}

fn parse_auth_protocol(value: &str) -> Option<AuthProtocol> {
    match value {
        "md5" => Some(AuthProtocol::Md5),
        "sha1" => Some(AuthProtocol::Sha1),
        "sha224" => Some(AuthProtocol::Sha224),
        "sha256" => Some(AuthProtocol::Sha256),
        "sha384" => Some(AuthProtocol::Sha384),
        "sha512" => Some(AuthProtocol::Sha512),
        _ => None,
    }
}

fn parse_priv_protocol(value: &str) -> Option<PrivProtocol> {
    match value {
        "des" => Some(PrivProtocol::Des),
        "3des" => Some(PrivProtocol::Des3),
        "aes128" => Some(PrivProtocol::Aes128),
        "aes192" => Some(PrivProtocol::Aes192Blumenthal),
        "aes256" => Some(PrivProtocol::Aes256Blumenthal),
        _ => None,
    }
}

fn parse_snmp_bindings(bindings: &[VarBind]) -> SnmpData {
    let mut data = SnmpData::default();
    let [sys_descr_oid, sys_uptime_oid, sys_name_oid] = system_oids();
    for binding in bindings {
        if binding.oid == sys_descr_oid {
            data.sys_descr = bounded_octet_string(&binding.value, 4096);
        } else if binding.oid == sys_name_oid {
            data.sys_name = bounded_octet_string(&binding.value, 253);
        } else if binding.oid == sys_uptime_oid {
            data.uptime_ticks = binding.value.as_u32();
            data.uptime_seconds = data
                .uptime_ticks
                .map(|centiseconds| f64::from(centiseconds) / 100.0);
        }
    }
    data
}

fn system_oids() -> [async_snmp::Oid; 3] {
    [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
    ]
}

async fn collect_optional_snmp(client: &Client) -> (Vec<PollMetric>, Vec<CounterSample>) {
    let (
        cpu,
        storage_types,
        storage_sizes,
        storage_used,
        hc_in,
        hc_out,
        in_octets,
        out_octets,
        names,
        descriptions,
        discontinuities,
    ) = tokio::join!(
        walk_optional(client, hr_processor_load_oid(), "hrProcessorLoad"),
        walk_optional(client, hr_storage_type_oid(), "hrStorageType"),
        walk_optional(client, hr_storage_size_oid(), "hrStorageSize"),
        walk_optional(client, hr_storage_used_oid(), "hrStorageUsed"),
        walk_optional(client, if_hc_in_octets_oid(), "ifHCInOctets"),
        walk_optional(client, if_hc_out_octets_oid(), "ifHCOutOctets"),
        walk_optional(client, if_in_octets_oid(), "ifInOctets"),
        walk_optional(client, if_out_octets_oid(), "ifOutOctets"),
        walk_optional(client, if_name_oid(), "ifName"),
        walk_optional(client, if_descr_oid(), "ifDescr"),
        walk_optional(
            client,
            if_counter_discontinuity_oid(),
            "ifCounterDiscontinuityTime"
        ),
    );

    let mut metrics = Vec::with_capacity(2);
    if let Some(cpu_percent) = average_cpu_percent(&cpu) {
        metrics.push(metric_with_series(
            "snmp_cpu_percent",
            cpu_percent,
            Some("percent"),
            "snmp",
            String::new(),
            json!({"probe": "snmp", "source": "hrProcessorLoad"}),
        ));
    }
    if let Some((memory_percent, storage_index)) =
        ram_used_percent(&storage_types, &storage_sizes, &storage_used)
    {
        metrics.push(metric_with_series(
            "snmp_memory_used_percent",
            memory_percent,
            Some("percent"),
            "snmp",
            String::new(),
            json!({"probe": "snmp", "source": "hrStorageTable", "hrStorageIndex": storage_index}),
        ));
    }

    let counters = interface_counter_samples(
        &hc_in,
        &hc_out,
        &in_octets,
        &out_octets,
        &names,
        &descriptions,
        &discontinuities,
    );
    (metrics, counters)
}

async fn walk_optional(
    client: &Client,
    root: async_snmp::Oid,
    table: &'static str,
) -> Vec<VarBind> {
    let options = WalkOptions {
        result_limit: Some(MAX_WALK_RESULTS),
        max_repetitions: 25,
        ..WalkOptions::default()
    };
    match client.walk_with(root, options) {
        Ok(stream) => match stream.collect().await {
            Ok(bindings) => bindings,
            Err(error) => {
                tracing::debug!(table, error = %error, "optional SNMP table walk failed");
                Vec::new()
            }
        },
        Err(error) => {
            tracing::debug!(table, error = %error, "optional SNMP table walk unavailable");
            Vec::new()
        }
    }
}

fn average_cpu_percent(bindings: &[VarBind]) -> Option<f64> {
    let root = hr_processor_load_oid();
    let values = bindings
        .iter()
        .filter(|binding| table_index(binding, &root).is_some())
        .filter_map(|binding| binding.value.as_u32())
        .filter(|value| *value <= 100)
        .map(f64::from)
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn ram_used_percent(types: &[VarBind], sizes: &[VarBind], used: &[VarBind]) -> Option<(f64, u32)> {
    let type_root = hr_storage_type_oid();
    let size_root = hr_storage_size_oid();
    let used_root = hr_storage_used_oid();
    let ram_type = hr_storage_ram_type_oid();
    let ram_indexes = types
        .iter()
        .filter_map(|binding| {
            let index = table_index(binding, &type_root)?;
            (binding.value.as_oid() == Some(&ram_type)).then_some(index)
        })
        .collect::<HashSet<_>>();
    let size_by_index = numeric_column(&size_root, sizes);
    let used_by_index = numeric_column(&used_root, used);
    ram_indexes
        .into_iter()
        .filter_map(|index| {
            let size = size_by_index.get(&index).copied()?;
            let used = used_by_index.get(&index).copied()?;
            (size > 0 && used <= size).then_some((f64::from(used) * 100.0 / f64::from(size), index))
        })
        .min_by_key(|(_, index)| *index)
}

fn numeric_column(root: &async_snmp::Oid, bindings: &[VarBind]) -> BTreeMap<u32, u32> {
    bindings
        .iter()
        .filter_map(|binding| Some((table_index(binding, root)?, binding.value.as_u32()?)))
        .collect()
}

fn interface_counter_samples(
    hc_in: &[VarBind],
    hc_out: &[VarBind],
    in_octets: &[VarBind],
    out_octets: &[VarBind],
    names: &[VarBind],
    descriptions: &[VarBind],
    discontinuities: &[VarBind],
) -> Vec<CounterSample> {
    let hc_in_root = if_hc_in_octets_oid();
    let hc_out_root = if_hc_out_octets_oid();
    let in_root = if_in_octets_oid();
    let out_root = if_out_octets_oid();
    let name_root = if_name_oid();
    let descr_root = if_descr_oid();
    let discontinuity_root = if_counter_discontinuity_oid();
    let high_in = counter64_column(&hc_in_root, hc_in);
    let high_out = counter64_column(&hc_out_root, hc_out);
    let low_in = counter32_column(&in_root, in_octets);
    let low_out = counter32_column(&out_root, out_octets);
    let name_by_index = text_column(&name_root, names, 255);
    let descr_by_index = text_column(&descr_root, descriptions, 255);
    let discontinuity_by_index = numeric_column(&discontinuity_root, discontinuities);
    let indexes = high_in
        .keys()
        .chain(high_out.keys())
        .chain(low_in.keys())
        .chain(low_out.keys())
        .copied()
        .collect::<HashSet<_>>();

    let mut samples = Vec::with_capacity(indexes.len() * 2);
    for index in indexes {
        let Some(if_index) = i32::try_from(index).ok() else {
            continue;
        };
        let if_name = name_by_index.get(&index).cloned();
        let if_descr = descr_by_index.get(&index).cloned();
        let discontinuity_ticks = discontinuity_by_index.get(&index).copied();
        if let Some(value) = high_in.get(&index).copied() {
            samples.push(CounterSample {
                if_index,
                direction: "in",
                value,
                bits: 64,
                if_name: if_name.clone(),
                if_descr: if_descr.clone(),
                discontinuity_ticks,
            });
        } else if let Some(value) = low_in.get(&index).copied() {
            samples.push(CounterSample {
                if_index,
                direction: "in",
                value,
                bits: 32,
                if_name: if_name.clone(),
                if_descr: if_descr.clone(),
                discontinuity_ticks,
            });
        }
        if let Some(value) = high_out.get(&index).copied() {
            samples.push(CounterSample {
                if_index,
                direction: "out",
                value,
                bits: 64,
                if_name: if_name.clone(),
                if_descr: if_descr.clone(),
                discontinuity_ticks,
            });
        } else if let Some(value) = low_out.get(&index).copied() {
            samples.push(CounterSample {
                if_index,
                direction: "out",
                value,
                bits: 32,
                if_name,
                if_descr,
                discontinuity_ticks,
            });
        }
    }
    samples
}

fn counter64_column(root: &async_snmp::Oid, bindings: &[VarBind]) -> BTreeMap<u32, u64> {
    bindings
        .iter()
        .filter_map(|binding| Some((table_index(binding, root)?, binding.value.as_u64()?)))
        .collect()
}

fn counter32_column(root: &async_snmp::Oid, bindings: &[VarBind]) -> BTreeMap<u32, u64> {
    bindings
        .iter()
        .filter_map(|binding| {
            Some((
                table_index(binding, root)?,
                u64::from(binding.value.as_u32()?),
            ))
        })
        .collect()
}

fn text_column(
    root: &async_snmp::Oid,
    bindings: &[VarBind],
    max_chars: usize,
) -> BTreeMap<u32, String> {
    bindings
        .iter()
        .filter_map(|binding| {
            Some((
                table_index(binding, root)?,
                bounded_octet_string(&binding.value, max_chars)?,
            ))
        })
        .collect()
}

fn table_index(binding: &VarBind, root: &async_snmp::Oid) -> Option<u32> {
    let suffix = binding.oid.strip_prefix(root)?;
    (suffix.len() == 1)
        .then(|| suffix.arcs().first().copied())
        .flatten()
        .filter(|index| *index > 0)
}

fn counter_rate(
    previous: Option<&CounterBaseline>,
    sample: &CounterSample,
    observed_at: DateTime<Utc>,
    uptime_ticks: Option<u32>,
) -> Option<f64> {
    let previous = previous?;
    if previous.counter_bits != sample.bits {
        return None;
    }
    let current_uptime = uptime_ticks.map(i64::from);
    match (previous.sys_uptime_ticks, current_uptime) {
        (Some(old), Some(new)) if new < old => return None,
        (Some(_), None) | (None, Some(_)) => return None,
        _ => {}
    }
    if matches!((previous.discontinuity_ticks, sample.discontinuity_ticks), (Some(old), Some(new)) if old != i64::from(new))
    {
        return None;
    }
    let old_value = previous.counter_value.parse::<u64>().ok()?;
    let delta = if sample.value >= old_value {
        sample.value - old_value
    } else if sample.bits == 32
        && matches!((previous.sys_uptime_ticks, current_uptime), (Some(old), Some(new)) if new >= old)
    {
        (1_u64 << 32)
            .checked_sub(old_value)?
            .checked_add(sample.value)?
    } else {
        return None;
    };
    let elapsed = observed_at
        .signed_duration_since(previous.observed_at)
        .to_std()
        .ok()?
        .as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    let rate = delta as f64 * 8.0 / elapsed;
    rate.is_finite().then_some(rate)
}

fn hr_processor_load_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2)
}
fn hr_storage_type_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2)
}
fn hr_storage_size_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5)
}
fn hr_storage_used_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6)
}
fn hr_storage_ram_type_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 25, 2, 1, 2)
}
fn if_in_octets_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10)
}
fn if_out_octets_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 16)
}
fn if_hc_in_octets_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6)
}
fn if_hc_out_octets_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10)
}
fn if_name_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
}
fn if_descr_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
}
fn if_counter_discontinuity_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 19)
}

fn bounded_octet_string(value: &Value, max_chars: usize) -> Option<String> {
    let value = value.as_str()?.trim();
    if value.is_empty() {
        return None;
    }
    let bounded = value.chars().take(max_chars).collect::<String>();
    Some(bounded)
}

async fn persist_poll(
    state: &AppState,
    device_id: Uuid,
    status: DeviceStatus,
    observed_at: DateTime<Utc>,
    sys_name: Option<String>,
    sys_descr: Option<String>,
    uptime_ticks: Option<u32>,
    metrics: &[PollMetric],
    counter_samples: &[CounterSample],
) -> Result<Vec<JsonValue>, sqlx::Error> {
    let mut transaction = state.db.begin().await?;
    let previous_status = sqlx::query!(
        "SELECT last_status FROM devices WHERE id = $1 AND is_enabled = TRUE AND deleted_at IS NULL FOR UPDATE",
        device_id
    )
    .fetch_optional(&mut *transaction)
    .await?
    .map(|row| row.last_status);
    let updated = sqlx::query!(
        r#"UPDATE devices
           SET last_status = $2,
               last_checked_at = $3,
               last_seen_at = CASE WHEN $2 <> 'down' THEN $3 ELSE last_seen_at END,
               consecutive_failures = CASE
                   WHEN $2 = 'down' THEN consecutive_failures + 1
                   ELSE 0
               END,
               sys_name = COALESCE($4, sys_name),
               sys_descr = COALESCE($5, sys_descr)
           WHERE id = $1 AND is_enabled = TRUE AND deleted_at IS NULL
           RETURNING id"#,
        device_id,
        status.as_str(),
        observed_at,
        sys_name,
        sys_descr
    )
    .fetch_optional(&mut *transaction)
    .await?;

    let mut events = Vec::new();
    let mut all_metrics = metrics.to_vec();
    if updated.is_some() {
        for sample in counter_samples {
            let previous = sqlx::query_as!(
                CounterBaseline,
                r#"SELECT counter_value AS "counter_value!", counter_bits,
                          observed_at, sys_uptime_ticks, discontinuity_ticks
                   FROM snmp_interface_counters
                   WHERE device_id = $1 AND if_index = $2 AND direction = $3
                   FOR UPDATE"#,
                device_id,
                sample.if_index,
                sample.direction
            )
            .fetch_optional(&mut *transaction)
            .await?;
            let rate = counter_rate(previous.as_ref(), sample, observed_at, uptime_ticks);
            sqlx::query!(
                r#"INSERT INTO snmp_interface_counters (
                       device_id, if_index, direction, counter_value, counter_bits, observed_at,
                       sys_uptime_ticks, discontinuity_ticks
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (device_id, if_index, direction) DO UPDATE SET
                       counter_value = EXCLUDED.counter_value,
                       counter_bits = EXCLUDED.counter_bits,
                       observed_at = EXCLUDED.observed_at,
                       sys_uptime_ticks = EXCLUDED.sys_uptime_ticks,
                       discontinuity_ticks = EXCLUDED.discontinuity_ticks"#,
                device_id,
                sample.if_index,
                sample.direction,
                sample.value.to_string(),
                sample.bits,
                observed_at,
                uptime_ticks.map(i64::from),
                sample.discontinuity_ticks.map(i64::from)
            )
            .execute(&mut *transaction)
            .await?;

            if let Some(rate) = rate {
                let metric_name = if sample.direction == "in" {
                    "snmp_if_in_bps"
                } else {
                    "snmp_if_out_bps"
                };
                all_metrics.push(metric_with_series(
                    metric_name,
                    rate,
                    Some("bps"),
                    "snmp",
                    format!("ifIndex={}", sample.if_index),
                    json!({
                        "probe": "snmp",
                        "ifIndex": sample.if_index,
                        "ifName": sample.if_name,
                        "ifDescr": sample.if_descr,
                        "direction": sample.direction
                    }),
                ));
            }
        }
    }
    if updated.is_some() && !all_metrics.is_empty() {
        let observed_at_values = vec![observed_at; all_metrics.len()];
        let device_ids = vec![device_id; all_metrics.len()];
        let metric_names = all_metrics
            .iter()
            .map(|metric| metric.name.clone())
            .collect::<Vec<_>>();
        let series_keys = all_metrics
            .iter()
            .map(|metric| metric.series_key.clone())
            .collect::<Vec<_>>();
        let values = all_metrics
            .iter()
            .map(|metric| metric.value)
            .collect::<Vec<_>>();
        let units = all_metrics
            .iter()
            .map(|metric| metric.unit.clone())
            .collect::<Vec<_>>();
        let labels = all_metrics
            .iter()
            .map(|metric| metric.labels.clone())
            .collect::<Vec<_>>();
        sqlx::query!(
            r#"INSERT INTO metrics (
                   observed_at, device_id, metric_name, series_key, value, unit, labels
               )
               SELECT observed_at, device_id, metric_name, series_key, value, unit, labels
               FROM UNNEST(
                   $1::timestamptz[], $2::uuid[], $3::text[], $4::text[],
                   $5::float8[], $6::text[], $7::jsonb[]
               ) AS batch(observed_at, device_id, metric_name, series_key, value, unit, labels)
               ON CONFLICT (observed_at, device_id, metric_name, series_key)
               DO UPDATE SET value = EXCLUDED.value, unit = EXCLUDED.unit, labels = EXCLUDED.labels"#,
            &observed_at_values,
            &device_ids,
            &metric_names,
            &series_keys,
            &values,
            &units,
            &labels
        )
        .execute(&mut *transaction)
        .await?;

        for metric in &all_metrics {
            events.extend(
                alerting::evaluate_metric(
                    &mut transaction,
                    device_id,
                    &metric.name,
                    &metric.series_key,
                    metric.value,
                    observed_at,
                )
                .await?,
            );
        }
    }
    if updated.is_some() && previous_status.as_deref() != Some(status.as_str()) {
        events.push(json!({
            "type": "device.status",
            "occurred_at": observed_at,
            "data": {"device_id": device_id, "status": status.as_str()}
        }));
    }
    transaction.commit().await.map(|()| events)
}

#[cfg(test)]
mod tests {
    use async_snmp::{Value, VarBind};
    use chrono::{Duration, TimeZone, Utc};
    use tokio::sync::Semaphore;

    use super::{
        CounterBaseline, CounterSample, DeviceStatus, average_cpu_percent, counter_rate,
        derive_status, hr_processor_load_oid, hr_storage_ram_type_oid, hr_storage_size_oid,
        hr_storage_type_oid, hr_storage_used_oid, if_hc_in_octets_oid, if_in_octets_oid,
        if_out_octets_oid, interface_counter_samples, metric_with_series, parse_auth_protocol,
        parse_priv_protocol, parse_snmp_bindings, ram_used_percent, reserve_available_permits,
        system_oids, table_index,
    };

    #[test]
    fn averages_valid_hr_processor_load_rows() {
        let root = hr_processor_load_oid();
        assert_eq!(
            average_cpu_percent(&[
                VarBind::new(root.child(1), Value::Integer(25)),
                VarBind::new(root.child(2), Value::Integer(75)),
                VarBind::new(root.child(3), Value::Integer(101)),
            ]),
            Some(50.0)
        );
        assert_eq!(average_cpu_percent(&[]), None);
    }

    #[test]
    fn accepts_only_a_single_positive_table_index_suffix() {
        let root = hr_processor_load_oid();
        assert_eq!(
            table_index(&VarBind::new(root.child(1), Value::Integer(20)), &root),
            Some(1)
        );
        assert_eq!(
            table_index(&VarBind::new(root.child(0), Value::Integer(20)), &root),
            None
        );
        assert_eq!(
            table_index(
                &VarBind::new(root.child(1).child(2), Value::Integer(20)),
                &root
            ),
            None
        );
    }

    #[test]
    fn selects_ram_storage_and_ignores_non_ram_rows() {
        let type_root = hr_storage_type_oid();
        let size_root = hr_storage_size_oid();
        let used_root = hr_storage_used_oid();
        let ram_type = hr_storage_ram_type_oid();
        let disk_type = ram_type.child(999);
        let result = ram_used_percent(
            &[
                VarBind::new(type_root.child(1), Value::ObjectIdentifier(ram_type)),
                VarBind::new(type_root.child(2), Value::ObjectIdentifier(disk_type)),
            ],
            &[
                VarBind::new(size_root.child(1), Value::Integer(100)),
                VarBind::new(size_root.child(2), Value::Integer(100)),
            ],
            &[
                VarBind::new(used_root.child(1), Value::Integer(40)),
                VarBind::new(used_root.child(2), Value::Integer(99)),
            ],
        );
        assert_eq!(result, Some((40.0, 1)));
    }

    #[test]
    fn prefers_hc_interface_counters_and_keeps_ifindex_series_identity() {
        let samples = interface_counter_samples(
            &[VarBind::new(
                if_hc_in_octets_oid().child(7),
                Value::Counter64(9_000_000_000),
            )],
            &[],
            &[VarBind::new(
                if_in_octets_oid().child(7),
                Value::Counter32(123),
            )],
            &[VarBind::new(
                if_out_octets_oid().child(7),
                Value::Counter32(456),
            )],
            &[VarBind::new(
                super::if_name_oid().child(7),
                Value::OctetString("eth7".into()),
            )],
            &[],
            &[],
        );
        let inbound = samples.iter().find(|sample| sample.direction == "in");
        let outbound = samples.iter().find(|sample| sample.direction == "out");
        assert_eq!(inbound.map(|sample| sample.value), Some(9_000_000_000));
        assert_eq!(inbound.map(|sample| sample.bits), Some(64));
        assert_eq!(
            inbound.and_then(|sample| sample.if_name.as_deref()),
            Some("eth7")
        );
        assert_eq!(outbound.map(|sample| sample.value), Some(456));
        assert_eq!(outbound.map(|sample| sample.bits), Some(32));

        let metric = metric_with_series(
            "snmp_if_in_bps",
            1.0,
            Some("bps"),
            "snmp",
            "ifIndex=7".to_owned(),
            serde_json::json!({"ifIndex": 7}),
        );
        assert_eq!(metric.series_key, "ifIndex=7");
    }

    fn baseline(
        value: &str,
        bits: i16,
        uptime: Option<i64>,
        discontinuity: Option<i64>,
    ) -> CounterBaseline {
        CounterBaseline {
            counter_value: value.to_owned(),
            counter_bits: bits,
            observed_at: Utc
                .timestamp_opt(1_000, 0)
                .single()
                .unwrap_or_else(Utc::now),
            sys_uptime_ticks: uptime,
            discontinuity_ticks: discontinuity,
        }
    }

    #[test]
    fn calculates_counter_rates_and_rejects_resets_or_ambiguous_changes() {
        let old_at = Utc
            .timestamp_opt(1_000, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let sample = CounterSample {
            if_index: 1,
            direction: "in",
            value: 1_600,
            bits: 64,
            if_name: None,
            if_descr: None,
            discontinuity_ticks: Some(50),
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("1000", 64, Some(10_000), Some(50))),
                &sample,
                old_at + Duration::seconds(2),
                Some(10_200),
            ),
            Some(2_400.0)
        );

        let precise = CounterSample {
            value: 9_007_199_254_742_993,
            ..sample.clone()
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("9007199254741993", 64, Some(10_000), Some(50))),
                &precise,
                old_at + Duration::seconds(1),
                Some(10_100),
            ),
            Some(8_000.0)
        );

        let wrapped = CounterSample {
            value: 10,
            bits: 32,
            ..sample.clone()
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("4294967290", 32, Some(10_000), Some(50))),
                &wrapped,
                old_at + Duration::seconds(1),
                Some(10_100),
            ),
            Some(128.0)
        );
        assert_eq!(
            counter_rate(
                Some(&baseline("4294967290", 32, Some(10_000), Some(50))),
                &wrapped,
                old_at + Duration::seconds(1),
                Some(10),
            ),
            None
        );
        let changed = CounterSample {
            discontinuity_ticks: Some(60),
            ..sample.clone()
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("1000", 64, Some(10_000), Some(50))),
                &changed,
                old_at + Duration::seconds(1),
                Some(10_100),
            ),
            None
        );
        let width_changed = CounterSample {
            bits: 32,
            ..sample.clone()
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("1000", 64, Some(10_000), Some(50))),
                &width_changed,
                old_at + Duration::seconds(1),
                Some(10_100),
            ),
            None
        );
        let reset = CounterSample {
            value: 5,
            ..sample.clone()
        };
        assert_eq!(
            counter_rate(
                Some(&baseline("1000", 64, Some(10_000), Some(50))),
                &reset,
                old_at + Duration::seconds(1),
                Some(10_100),
            ),
            None
        );
        assert_eq!(
            counter_rate(None, &sample, old_at + Duration::seconds(1), Some(10_100)),
            None
        );
    }

    #[test]
    fn maps_supported_snmpv3_authentication_protocols() {
        assert_eq!(
            parse_auth_protocol("md5"),
            Some(async_snmp::AuthProtocol::Md5)
        );
        assert_eq!(
            parse_auth_protocol("sha1"),
            Some(async_snmp::AuthProtocol::Sha1)
        );
        assert_eq!(
            parse_auth_protocol("sha224"),
            Some(async_snmp::AuthProtocol::Sha224)
        );
        assert_eq!(
            parse_auth_protocol("sha256"),
            Some(async_snmp::AuthProtocol::Sha256)
        );
        assert_eq!(
            parse_auth_protocol("sha384"),
            Some(async_snmp::AuthProtocol::Sha384)
        );
        assert_eq!(
            parse_auth_protocol("sha512"),
            Some(async_snmp::AuthProtocol::Sha512)
        );
        assert_eq!(parse_auth_protocol("unsupported"), None);
    }

    #[test]
    fn maps_supported_snmpv3_privacy_protocols() {
        assert_eq!(
            parse_priv_protocol("des"),
            Some(async_snmp::PrivProtocol::Des)
        );
        assert_eq!(
            parse_priv_protocol("3des"),
            Some(async_snmp::PrivProtocol::Des3)
        );
        assert_eq!(
            parse_priv_protocol("aes128"),
            Some(async_snmp::PrivProtocol::Aes128)
        );
        assert_eq!(
            parse_priv_protocol("aes192"),
            Some(async_snmp::PrivProtocol::Aes192Blumenthal)
        );
        assert_eq!(
            parse_priv_protocol("aes256"),
            Some(async_snmp::PrivProtocol::Aes256Blumenthal)
        );
        assert_eq!(parse_priv_protocol("unsupported"), None);
    }

    #[test]
    fn parses_system_identity_and_uptime_from_snmp_bindings() {
        let [sys_descr, sys_uptime, sys_name] = system_oids();
        let data = parse_snmp_bindings(&[
            VarBind::new(
                sys_descr,
                Value::OctetString("Linux network appliance".into()),
            ),
            VarBind::new(sys_uptime, Value::TimeTicks(123_450)),
            VarBind::new(sys_name, Value::OctetString("edge-sw-01".into())),
        ]);
        assert_eq!(data.sys_descr.as_deref(), Some("Linux network appliance"));
        assert_eq!(data.sys_name.as_deref(), Some("edge-sw-01"));
        assert_eq!(data.uptime_seconds, Some(1234.5));
    }

    #[test]
    fn maps_probe_successes_to_up_degraded_or_down() {
        assert_eq!(derive_status(&[true, true]), DeviceStatus::Up);
        assert_eq!(derive_status(&[true, false]), DeviceStatus::Degraded);
        assert_eq!(derive_status(&[false, false]), DeviceStatus::Down);
    }

    #[test]
    fn reserves_only_available_global_probe_permits() {
        let semaphore = std::sync::Arc::new(Semaphore::new(2));
        let first = reserve_available_permits(&semaphore, 8);
        assert_eq!(first.len(), 2);
        assert_eq!(semaphore.available_permits(), 0);
        drop(first);
        assert_eq!(semaphore.available_permits(), 2);
    }
}
