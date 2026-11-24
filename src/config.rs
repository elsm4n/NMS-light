use std::{net::SocketAddr, path::Path};

use config::{Config, Environment};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Deserialize)]
struct RawSettings {
    database_url: String,
    listen_addr: String,
    jwt_secret: String,
    credential_key_hex: String,
    discovery_cidrs: String,
    max_probe_concurrency: usize,
    bootstrap_admin_email: Option<String>,
    bootstrap_admin_password: Option<String>,
}

pub struct AppConfig {
    pub database_url: String,
    pub listen_addr: SocketAddr,
    pub jwt_secret: String,
    pub credential_key: [u8; 32],
    pub discovery_networks: Vec<IpNet>,
    pub max_probe_concurrency: usize,
    pub bootstrap_admin_email: Option<String>,
    pub bootstrap_admin_password: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        if Path::new(".env").exists() {
            dotenvy::dotenv()?;
        }

        let raw: RawSettings = Config::builder()
            .set_default("listen_addr", "127.0.0.1:8080")?
            .set_default("discovery_cidrs", "")?
            .set_default("max_probe_concurrency", 32)?
            .add_source(
                Environment::with_prefix("NMS")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()?;

        let listen_addr = raw.listen_addr.parse::<SocketAddr>()?;
        let discovery_networks = parse_discovery_networks(&raw.discovery_cidrs)?;
        if !(1..=512).contains(&raw.max_probe_concurrency) {
            anyhow::bail!("NMS_MAX_PROBE_CONCURRENCY must be between 1 and 512");
        }
        if raw.jwt_secret.as_bytes().len() < 32 {
            anyhow::bail!("NMS_JWT_SECRET must contain at least 32 bytes");
        }

        let key_bytes = hex::decode(raw.credential_key_hex.trim())?;
        let credential_key = <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("NMS_CREDENTIAL_KEY_HEX must encode exactly 32 bytes"))?;

        if raw.bootstrap_admin_email.is_some() != raw.bootstrap_admin_password.is_some() {
            anyhow::bail!(
                "NMS_BOOTSTRAP_ADMIN_EMAIL and NMS_BOOTSTRAP_ADMIN_PASSWORD must be set together"
            );
        }

        Ok(Self {
            database_url: raw.database_url,
            listen_addr,
            jwt_secret: raw.jwt_secret,
            credential_key,
            discovery_networks,
            max_probe_concurrency: raw.max_probe_concurrency,
            bootstrap_admin_email: raw.bootstrap_admin_email,
            bootstrap_admin_password: raw.bootstrap_admin_password,
        })
    }
}

fn parse_discovery_networks(value: &str) -> anyhow::Result<Vec<IpNet>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut networks = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            anyhow::bail!("NMS_DISCOVERY_CIDRS must not contain empty entries");
        }
        let network = entry.parse::<IpNet>().map_err(|_| {
            anyhow::anyhow!("NMS_DISCOVERY_CIDRS contains an invalid CIDR entry: {entry}")
        })?;
        if !networks.contains(&network) {
            networks.push(network);
        }
    }
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ipnet::IpNet;

    use super::parse_discovery_networks;

    #[test]
    fn empty_discovery_allowlist_disables_discovery() -> Result<(), Box<dyn Error>> {
        assert!(parse_discovery_networks("")?.is_empty());
        Ok(())
    }

    #[test]
    fn parses_and_deduplicates_ipv4_and_ipv6_networks() -> Result<(), Box<dyn Error>> {
        let networks = parse_discovery_networks("192.168.1.0/24, fd00::/64, 192.168.1.0/24")?;
        let expected: Vec<IpNet> = vec!["192.168.1.0/24".parse()?, "fd00::/64".parse()?];
        assert_eq!(networks, expected);
        Ok(())
    }

    #[test]
    fn rejects_invalid_or_empty_cidr_entries() {
        assert!(parse_discovery_networks("192.168.1.0/24,not-a-cidr").is_err());
        assert!(parse_discovery_networks("192.168.1.0/24,").is_err());
    }
}
