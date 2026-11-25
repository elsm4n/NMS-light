use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio_util::sync::CancellationToken;

use crate::auth::hash_password;

const METRICS_CHUNK_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60 * 60);

const ENSURE_METRICS_CHUNKS_SQL: &str = r#"
WITH RECURSIVE dimension AS (
    SELECT time_interval
    FROM timescaledb_information.dimensions
    WHERE hypertable_schema = 'public'
      AND hypertable_name = 'metrics'
      AND column_name = 'observed_at'
      AND dimension_type = 'Time'
), current_chunk AS (
    SELECT chunk.range_start, chunk.range_end
    FROM timescaledb_information.chunks AS chunk
    WHERE chunk.hypertable_schema = 'public'
      AND chunk.hypertable_name = 'metrics'
      AND chunk.range_start <= $1
      AND $1 < chunk.range_end
    ORDER BY chunk.range_start DESC
    LIMIT 1
), chunk_chain AS (
    SELECT range_start, range_end, 0 AS depth
    FROM current_chunk
    UNION ALL
    SELECT next_chunk.range_start, next_chunk.range_end, chunk_chain.depth + 1
    FROM chunk_chain
    JOIN timescaledb_information.chunks AS next_chunk
      ON next_chunk.hypertable_schema = 'public'
     AND next_chunk.hypertable_name = 'metrics'
     AND next_chunk.range_start = chunk_chain.range_end
), bounds AS (
    SELECT COALESCE(
        (
            SELECT range_end
            FROM chunk_chain
            ORDER BY depth DESC
            LIMIT 1
        ),
        time_bucket(dimension.time_interval, $1)
    ) AS chunk_start, dimension.time_interval
    FROM dimension
), targets AS (
    SELECT chunk_start + step.n * time_interval AS chunk_start, time_interval
    FROM bounds
    CROSS JOIN generate_series(0, 1) AS step(n)
)
SELECT count(*)::bigint
FROM targets
CROSS JOIN LATERAL _timescaledb_functions.create_chunk(
    'public.metrics'::regclass,
    jsonb_build_object(
        'observed_at',
        jsonb_build_array(
            (extract(epoch FROM chunk_start) * 1000000)::bigint,
            (extract(epoch FROM chunk_start + time_interval) * 1000000)::bigint
        )
    )
);
"#;

pub async fn connect_and_migrate(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    ensure_metrics_chunks_at(&pool, Utc::now()).await?;
    Ok(pool)
}

pub async fn ensure_metrics_chunks_at(
    pool: &PgPool,
    reference_time: DateTime<Utc>,
) -> anyhow::Result<()> {
    let chunks = sqlx::query_scalar::<_, i64>(ENSURE_METRICS_CHUNKS_SQL)
        .bind(reference_time)
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        chunks == 2,
        "metrics hypertable must have one time dimension"
    );
    Ok(())
}

pub async fn run_metrics_chunk_maintenance(pool: PgPool, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(METRICS_CHUNK_MAINTENANCE_INTERVAL);
    interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                if let Err(error) = ensure_metrics_chunks_at(&pool, Utc::now()).await {
                    tracing::error!(error = %error, "metrics chunk pre-creation failed");
                }
            }
        }
    }

    tracing::info!("metrics chunk maintenance stopped");
}

pub async fn bootstrap_admin(
    pool: &PgPool,
    email: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let row = sqlx::query!("SELECT COUNT(*) AS \"count!\" FROM users")
        .fetch_one(pool)
        .await?;

    if row.count > 0 {
        return Ok(());
    }

    let (email, password) = match (email, password) {
        (Some(email), Some(password)) => (email.trim().to_lowercase(), password),
        _ => anyhow::bail!(
            "no users exist: set NMS_BOOTSTRAP_ADMIN_EMAIL and NMS_BOOTSTRAP_ADMIN_PASSWORD for first startup"
        ),
    };

    if email.is_empty() || password.chars().count() < 16 {
        anyhow::bail!(
            "bootstrap admin requires a non-empty email and a password of at least 16 characters"
        );
    }

    let password_hash = hash_password(password)?;
    sqlx::query!(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin')",
        email,
        password_hash
    )
    .execute(pool)
    .await?;

    tracing::info!("created the initial administrator account");
    Ok(())
}
