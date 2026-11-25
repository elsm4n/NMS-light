use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use rust_nms::{api, config::AppConfig, crypto::SecretCipher, db, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = AppConfig::from_env()?;

    let pool = db::connect_and_migrate(&config.database_url).await?;
    db::bootstrap_admin(
        &pool,
        config.bootstrap_admin_email.as_deref(),
        config.bootstrap_admin_password.as_deref(),
    )
    .await?;

    let shutdown = CancellationToken::new();
    let state = AppState::new(
        pool,
        config.jwt_secret.into_bytes(),
        SecretCipher::new(config.credential_key),
        config.discovery_networks,
        config.max_probe_concurrency,
        shutdown.clone(),
    );
    let metrics_chunk_worker = tokio::spawn(db::run_metrics_chunk_maintenance(
        state.db.clone(),
        shutdown.clone(),
    ));
    let polling_worker = tokio::spawn(rust_nms::polling::run(state.clone(), shutdown.clone()));
    let webhook_worker = tokio::spawn(rust_nms::webhook_dispatcher::run(
        state.clone(),
        shutdown.clone(),
    ));
    let app = api::router(state);
    let listener = TcpListener::bind(config.listen_addr).await?;
    tracing::info!(address = %config.listen_addr, "NMS API listening");

    let server_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown.clone()))
    .await;
    shutdown.cancel();
    polling_worker.await?;
    webhook_worker.await?;
    metrics_chunk_worker.await?;
    server_result?;

    Ok(())
}

fn init_tracing() {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("info"),
    };
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}

async fn shutdown_signal(shutdown: CancellationToken) {
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                let _ = signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to register SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(error = %error, "failed to register Ctrl-C handler");
            }
        }
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
    shutdown.cancel();
}
