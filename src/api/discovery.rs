use axum::{Json, extract::State};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    auth::AuthUser,
    discovery::{is_allowed_subnet, ping_hosts, targets_for_subnet},
    error::ApiError,
    state::AppState,
};

#[derive(Deserialize)]
pub struct DiscoveryRequest {
    cidr: String,
}

#[derive(Serialize)]
pub struct DiscoveryResponse {
    pub cidr: String,
    pub scanned: usize,
    pub reachable: usize,
    pub added: usize,
    pub hosts: Vec<DiscoveredHost>,
}

#[derive(Serialize)]
pub struct DiscoveredHost {
    pub ip_address: String,
    pub added: bool,
}

pub async fn scan(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<DiscoveryRequest>,
) -> Result<Json<DiscoveryResponse>, ApiError> {
    user.require_inventory_write()?;
    if state.discovery_networks.is_empty() {
        return Err(ApiError::Forbidden);
    }

    let subnet = request
        .cidr
        .parse::<IpNet>()
        .map_err(|_| ApiError::BadRequest("cidr must be a valid IPv4 or IPv6 network"))?;
    if !is_allowed_subnet(&subnet, &state.discovery_networks) {
        return Err(ApiError::Forbidden);
    }

    let targets = targets_for_subnet(&subnet)
        .map_err(|_| ApiError::BadRequest("cidr contains more than 1024 host addresses"))?;
    let scanned = targets.len();
    let reachable = ping_hosts(
        targets,
        state.probe_semaphore.clone(),
        state.max_probe_concurrency,
    )
    .await
    .map_err(|_| ApiError::Internal)?;
    let reachable_count = reachable.len();

    let mut transaction = state.db.begin().await?;
    let mut hosts = Vec::with_capacity(reachable_count);
    let mut added = 0;
    for address in reachable {
        let ip_network = IpNet::from(address);
        let inserted_id = sqlx::query_scalar!(
            r#"INSERT INTO devices (
                ip_address, device_type, last_status, last_checked_at, last_seen_at
            ) VALUES ($1, 'other', 'up', now(), now())
            ON CONFLICT (ip_address) DO NOTHING
            RETURNING id"#,
            ip_network
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let was_added = inserted_id.is_some();
        if was_added {
            added += 1;
        }
        hosts.push(DiscoveredHost {
            ip_address: address.to_string(),
            added: was_added,
        });
    }
    transaction.commit().await?;

    Ok(Json(DiscoveryResponse {
        cidr: subnet.to_string(),
        scanned,
        reachable: reachable_count,
        added,
        hosts,
    }))
}
