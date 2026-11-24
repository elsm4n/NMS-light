use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ipnet::IpNet;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    auth::{AuthUser, UserRole},
    crypto::SecretCipher,
};

const WS_TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_WS_TICKETS: usize = 4096;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: Arc<[u8]>,
    pub credential_cipher: SecretCipher,
    pub discovery_networks: Arc<[IpNet]>,
    pub max_probe_concurrency: usize,
    pub probe_semaphore: Arc<Semaphore>,
    pub events: broadcast::Sender<JsonValue>,
    pub shutdown: CancellationToken,
    ws_tickets: Arc<Mutex<HashMap<String, (Uuid, UserRole, Instant)>>>,
}

impl AppState {
    pub fn new(
        db: PgPool,
        jwt_secret: Vec<u8>,
        credential_cipher: SecretCipher,
        discovery_networks: Vec<IpNet>,
        max_probe_concurrency: usize,
        shutdown: CancellationToken,
    ) -> Self {
        let max_probe_concurrency = max_probe_concurrency.max(1);
        let (events, _) = broadcast::channel(1024);
        Self {
            db,
            jwt_secret: Arc::from(jwt_secret),
            credential_cipher,
            discovery_networks: Arc::from(discovery_networks),
            max_probe_concurrency,
            probe_semaphore: Arc::new(Semaphore::new(max_probe_concurrency)),
            events,
            shutdown,
            ws_tickets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn issue_ws_ticket(&self, user_id: Uuid, role: UserRole) -> anyhow::Result<String> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)?;
        let ticket = hex::encode(bytes);
        let now = Instant::now();
        let mut tickets = self.ws_tickets.lock().await;
        tickets.retain(|_, (_, _, expires_at)| *expires_at > now);
        if tickets.len() >= MAX_WS_TICKETS {
            if let Some(oldest) = tickets
                .iter()
                .min_by_key(|(_, (_, _, expires_at))| *expires_at)
                .map(|(ticket, _)| ticket.clone())
            {
                tickets.remove(&oldest);
            }
        }
        tickets.insert(ticket.clone(), (user_id, role, now + WS_TICKET_TTL));
        Ok(ticket)
    }

    pub async fn consume_ws_ticket(&self, ticket: &str) -> Option<AuthUser> {
        let entry = self.ws_tickets.lock().await.remove(ticket)?;
        if entry.2 <= Instant::now() {
            return None;
        }
        Some(AuthUser {
            id: entry.0,
            role: entry.1,
        })
    }
}
