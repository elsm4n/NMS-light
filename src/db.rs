use std::time::Duration;

use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::auth::hash_password;

pub async fn connect_and_migrate(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
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
