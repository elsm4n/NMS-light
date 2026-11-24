mod alert_preflight;
mod alerts;
mod auth;
mod devices;
mod discovery;
mod health;
mod webhooks;
mod websocket;

use axum::{
    Router,
    routing::{get, patch, post, put},
};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/ws-ticket", post(auth::websocket_ticket))
        .route("/api/v1/ws", get(websocket::upgrade))
        .route("/api/v1/discovery/scans", post(discovery::scan))
        .route("/api/v1/alerts/preflight", post(alert_preflight::preflight))
        .route(
            "/api/v1/alerts/rules",
            get(alerts::list_rules).post(alerts::create_rule),
        )
        .route("/api/v1/alerts/rules/{id}", put(alerts::update_rule))
        .route(
            "/api/v1/alerts/rules/{id}/enabled",
            patch(alerts::set_rule_enabled),
        )
        .route("/api/v1/alerts", get(alerts::list_alerts))
        .route("/api/v1/alerts/events", get(alerts::list_events))
        .route(
            "/api/v1/webhooks",
            get(webhooks::list).post(webhooks::create),
        )
        .route("/api/v1/webhooks/{id}", put(webhooks::update))
        .route(
            "/api/v1/webhooks/{id}/enabled",
            patch(webhooks::set_enabled),
        )
        .route("/api/v1/devices", get(devices::list).post(devices::create))
        .route(
            "/api/v1/devices/{id}",
            get(devices::get_one)
                .put(devices::update)
                .delete(devices::delete),
        )
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
