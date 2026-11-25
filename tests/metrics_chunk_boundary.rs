use std::{env, time::Duration as StdDuration, time::Instant};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rust_nms::{alerting, db::ensure_metrics_chunks_at};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{sync::Barrier, task::JoinSet};
use uuid::Uuid;

#[derive(Debug)]
struct BatchResult {
    elapsed: StdDuration,
    latencies: Vec<StdDuration>,
    successes: usize,
    errors: usize,
    deadlocks: usize,
}

#[tokio::test]
#[ignore = "memerlukan PostgreSQL 17 + TimescaleDB khusus dan database rust_nms_chunk_deadlock_test_*"]
async fn concurrent_chunk_boundary_benchmark() -> anyhow::Result<()> {
    let database_url = env::var("NMS_CHUNK_BOUNDARY_TEST_DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(32)
        .acquire_timeout(StdDuration::from_secs(30))
        .connect(&database_url)
        .await?;

    let (database_name, server_version, available_timescaledb): (String, String, Option<String>) =
        sqlx::query_as(
            "SELECT current_database(), current_setting('server_version'), (SELECT default_version FROM pg_available_extensions WHERE name='timescaledb')",
        )
        .fetch_one(&pool)
        .await?;
    anyhow::ensure!(
        database_name.starts_with("rust_nms_chunk_deadlock_test_"),
        "refusing non-test database {database_name}"
    );
    anyhow::ensure!(
        server_version.starts_with("17.12"),
        "expected PostgreSQL 17.12, got {server_version}"
    );
    anyhow::ensure!(
        available_timescaledb.as_deref() == Some("2.32.1"),
        "expected TimescaleDB 2.32.1, got {available_timescaledb:?}"
    );

    sqlx::migrate!("./migrations").run(&pool).await?;
    let installed_timescaledb: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname='timescaledb'")
            .fetch_one(&pool)
            .await?;
    anyhow::ensure!(installed_timescaledb == "2.32.1");

    // Mirrors application startup: create current/future chunks before polling starts.
    ensure_metrics_chunks_at(&pool, Utc::now()).await?;
    let devices = seed_devices(&pool, 500).await?;
    let concurrency = [8, 16, 32];
    let mut target = latest_chunk_end(&pool).await?;

    // Cold control: no target chunk exists when concurrent transactions write devices then metrics.
    for limit in concurrency {
        let metric_name = format!("cold_boundary_{limit}");
        let previous_sample = target.clone() - ChronoDuration::seconds(1);
        insert_warmup(&pool, devices[0], previous_sample.clone(), &metric_name).await?;
        anyhow::ensure!(
            !chunk_exists(&pool, target.clone()).await?,
            "cold-path target chunk already existed before concurrent insert"
        );

        let result = run_batch(&pool, &devices, target.clone(), &metric_name, limit).await?;
        anyhow::ensure!(
            chunk_exists(&pool, target.clone()).await?,
            "concurrent insert did not create the target chunk"
        );
        anyhow::ensure!(result.successes + result.errors == 500);
        anyhow::ensure!(
            result.errors == result.deadlocks,
            "cold path had {} non-deadlock errors",
            result.errors - result.deadlocks
        );
        anyhow::ensure!(
            result.deadlocks > 0,
            "cold path did not reproduce the expected concurrent chunk-creation deadlock"
        );
        print_result("cold-create", limit, &result);
        let stored = stored_rows(&pool, target.clone(), &metric_name).await?;
        println!("cold-create rows: {stored}/500");
        target = chunk_end_for(&pool, target).await?;
    }

    // Fixed path: create the exact next range in a separate transaction before concurrent inserts.
    for limit in concurrency {
        let metric_name = format!("precreated_boundary_{limit}");
        let previous_sample = target.clone() - ChronoDuration::seconds(1);
        insert_warmup(&pool, devices[0], previous_sample.clone(), &metric_name).await?;
        anyhow::ensure!(
            !chunk_exists(&pool, target.clone()).await?,
            "pre-create target chunk unexpectedly existed"
        );

        ensure_metrics_chunks_at(&pool, previous_sample).await?;
        anyhow::ensure!(
            chunk_exists(&pool, target.clone()).await?,
            "maintenance helper did not pre-create the target chunk"
        );
        let result = run_batch(&pool, &devices, target.clone(), &metric_name, limit).await?;
        anyhow::ensure!(
            result.errors == 0,
            "pre-created boundary had {} database errors ({} deadlocks)",
            result.errors,
            result.deadlocks
        );
        print_result("precreated", limit, &result);
        let stored = stored_rows(&pool, target.clone(), &metric_name).await?;
        anyhow::ensure!(
            stored == 500,
            "pre-created boundary stored {stored}/500 rows"
        );
        println!("precreated rows: {stored}/500");
        let first_precreated_end = chunk_end_for(&pool, target).await?;
        target = chunk_end_for(&pool, first_precreated_end).await?;
    }

    verify_outbox_remains_pending_without_dispatch(&pool, devices[0]).await?;
    pool.close().await;
    Ok(())
}

async fn seed_devices(pool: &PgPool, count: usize) -> anyhow::Result<Vec<Uuid>> {
    let mut ids = Vec::with_capacity(count);
    let address_seed = u32::from_be_bytes(Uuid::new_v4().as_bytes()[..4].try_into()?);
    for index in 0..count {
        let id = Uuid::new_v4();
        let address = (address_seed + index as u32) % (1 << 17);
        let ip = format!(
            "198.{}.{}.{}",
            18 + address / 65_536,
            (address / 256) % 256,
            address % 256
        );
        sqlx::query(
            "INSERT INTO devices (id, ip_address, device_type) VALUES ($1, $2::inet, 'server')",
        )
        .bind(id)
        .bind(ip)
        .execute(pool)
        .await?;
        ids.push(id);
    }
    Ok(ids)
}

async fn latest_chunk_end(pool: &PgPool) -> anyhow::Result<DateTime<Utc>> {
    let end: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(range_end) FROM timescaledb_information.chunks WHERE hypertable_schema='public' AND hypertable_name='metrics'",
    )
    .fetch_one(pool)
    .await?;
    end.ok_or_else(|| anyhow::anyhow!("startup did not create any metrics chunks"))
}

async fn chunk_end_for(pool: &PgPool, timestamp: DateTime<Utc>) -> anyhow::Result<DateTime<Utc>> {
    let end: Option<DateTime<Utc>> = sqlx::query_scalar(
        r#"SELECT range_end
           FROM timescaledb_information.chunks
           WHERE hypertable_schema='public' AND hypertable_name='metrics'
             AND range_start <= $1 AND $1 < range_end
           ORDER BY range_start DESC LIMIT 1"#,
    )
    .bind(timestamp)
    .fetch_optional(pool)
    .await?;
    end.ok_or_else(|| anyhow::anyhow!("no metrics chunk contains {timestamp}"))
}

async fn insert_warmup(
    pool: &PgPool,
    device_id: Uuid,
    observed_at: DateTime<Utc>,
    metric_name: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO metrics (observed_at, device_id, metric_name, value, unit) VALUES ($1, $2, $3, 0, '1')",
    )
    .bind(observed_at.clone())
    .bind(device_id)
    .bind(metric_name)
    .execute(pool)
    .await?;
    anyhow::ensure!(chunk_exists(pool, observed_at).await?);
    Ok(())
}

async fn chunk_exists(pool: &PgPool, timestamp: DateTime<Utc>) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM timescaledb_information.chunks
               WHERE hypertable_schema = 'public'
                 AND hypertable_name = 'metrics'
                 AND range_start <= $1 AND $1 < range_end
           )"#,
    )
    .bind(timestamp)
    .fetch_one(pool)
    .await
}

async fn stored_rows(
    pool: &PgPool,
    observed_at: DateTime<Utc>,
    metric_name: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM metrics WHERE observed_at=$1 AND metric_name=$2")
        .bind(observed_at)
        .bind(metric_name)
        .fetch_one(pool)
        .await
}

async fn run_batch(
    pool: &PgPool,
    devices: &[Uuid],
    observed_at: DateTime<Utc>,
    metric_name: &str,
    concurrency: usize,
) -> anyhow::Result<BatchResult> {
    let started = Instant::now();
    let mut result = BatchResult {
        elapsed: StdDuration::ZERO,
        latencies: Vec::with_capacity(devices.len()),
        successes: 0,
        errors: 0,
        deadlocks: 0,
    };

    for wave in devices.chunks(concurrency) {
        let barrier = std::sync::Arc::new(Barrier::new(wave.len()));
        let mut tasks = JoinSet::new();
        for device_id in wave.iter().copied() {
            let pool = pool.clone();
            let barrier = barrier.clone();
            let metric_name = metric_name.to_owned();
            let observed_at = observed_at.clone();
            tasks.spawn(async move {
                poll_write(&pool, device_id, observed_at, &metric_name, barrier).await
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let (latency, outcome) = joined?;
            result.latencies.push(latency);
            match outcome {
                Ok(()) => result.successes += 1,
                Err(error) => {
                    result.errors += 1;
                    if error
                        .as_database_error()
                        .and_then(|database_error| database_error.code())
                        .as_deref()
                        == Some("40P01")
                    {
                        result.deadlocks += 1;
                    }
                }
            }
        }
    }

    result.elapsed = started.elapsed();
    Ok(result)
}

async fn poll_write(
    pool: &PgPool,
    device_id: Uuid,
    observed_at: DateTime<Utc>,
    metric_name: &str,
    barrier: std::sync::Arc<Barrier>,
) -> (StdDuration, Result<(), sqlx::Error>) {
    let started = Instant::now();
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            barrier.wait().await;
            return (started.elapsed(), Err(error));
        }
    };
    if let Err(error) = sqlx::query(
        "UPDATE devices SET last_status='up', last_checked_at=$2, last_seen_at=$2 WHERE id=$1",
    )
    .bind(device_id)
    .bind(observed_at.clone())
    .execute(&mut *transaction)
    .await
    {
        barrier.wait().await;
        return (started.elapsed(), Err(error));
    }

    // All workers hold the parent-table RowExclusiveLock before any can create a chunk.
    barrier.wait().await;
    let write = sqlx::query(
        r#"INSERT INTO metrics (observed_at, device_id, metric_name, series_key, value, unit)
           VALUES ($1, $2, $3, '', 1, '1')
           ON CONFLICT (observed_at, device_id, metric_name, series_key)
           DO UPDATE SET value=EXCLUDED.value"#,
    )
    .bind(observed_at)
    .bind(device_id)
    .bind(metric_name)
    .execute(&mut *transaction)
    .await;
    match write {
        Ok(_) => (started.elapsed(), transaction.commit().await),
        Err(error) => (started.elapsed(), Err(error)),
    }
}

fn print_result(label: &str, concurrency: usize, result: &BatchResult) {
    let mut latencies = result.latencies.clone();
    latencies.sort_unstable();
    let p95 = percentile_ms(&latencies, 0.95);
    let p99 = percentile_ms(&latencies, 0.99);
    let throughput = result.successes as f64 / result.elapsed.as_secs_f64();
    println!(
        "{label} c={concurrency} rows={}/500 errors={} deadlocks={} throughput={throughput:.1} rows/s wall={:.3}s p95={p95:.2}ms p99={p99:.2}ms",
        result.successes,
        result.errors,
        result.deadlocks,
        result.elapsed.as_secs_f64(),
    );
}

fn percentile_ms(sorted: &[StdDuration], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (percentile * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)].as_secs_f64() * 1000.0
}

async fn verify_outbox_remains_pending_without_dispatch(
    pool: &PgPool,
    device_id: Uuid,
) -> anyhow::Result<()> {
    let endpoint_id = Uuid::new_v4();
    let rule_id = Uuid::new_v4();
    let metric_name = format!("outbox_probe_{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO webhook_endpoints (id, name, provider, config_ciphertext) VALUES ($1, 'local test only', 'generic', $2)",
    )
    .bind(endpoint_id)
    .bind(vec![0_u8])
    .execute(pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO alert_rules (
               id, name, metric_name, comparison, critical_threshold,
               consecutive_failures, recovery_successes, cooldown_seconds,
               device_selector, is_enabled
           ) VALUES ($1, 'chunk boundary outbox test', $2, 'gt', 0,
                     1, 2, 0, '{}'::jsonb, TRUE)"#,
    )
    .bind(rule_id)
    .bind(&metric_name)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO alert_rule_endpoints (rule_id, endpoint_id) VALUES ($1, $2)")
        .bind(rule_id)
        .bind(endpoint_id)
        .execute(pool)
        .await?;

    let observed_at = Utc::now();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO metrics (observed_at, device_id, metric_name, value, unit) VALUES ($1, $2, $3, 1, '1')",
    )
    .bind(observed_at.clone())
    .bind(device_id)
    .bind(&metric_name)
    .execute(&mut *transaction)
    .await?;
    alerting::evaluate_metric(
        &mut transaction,
        device_id,
        &metric_name,
        "",
        1.0,
        observed_at,
    )
    .await?;
    transaction.commit().await?;

    let (status, attempt_count, delivered_at): (String, i32, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT status, attempt_count, delivered_at FROM notification_outbox WHERE endpoint_id=$1",
        )
        .bind(endpoint_id)
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(status == "pending");
    anyhow::ensure!(attempt_count == 0);
    anyhow::ensure!(delivered_at.is_none());
    println!(
        "outbox: status={status}, attempts={attempt_count}, delivered=false; dispatcher/webhook not started"
    );
    Ok(())
}
