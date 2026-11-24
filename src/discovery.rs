use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt, stream};
use ipnet::IpNet;
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};
use thiserror::Error;
use tokio::sync::Semaphore;

const MAX_DISCOVERY_HOSTS: usize = 1024;
const ICMP_TIMEOUT: Duration = Duration::from_millis(900);
static NEXT_PING_IDENTIFIER: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("discovery subnet exceeds the supported host limit")]
    TooManyHosts,
    #[error("probe concurrency semaphore has been closed")]
    SemaphoreClosed,
}

pub fn is_allowed_subnet(requested: &IpNet, allowlist: &[IpNet]) -> bool {
    allowlist.iter().any(|allowed| allowed.contains(requested))
}

pub fn targets_for_subnet(subnet: &IpNet) -> Result<Vec<IpAddr>, DiscoveryError> {
    let targets = subnet
        .hosts()
        .take(MAX_DISCOVERY_HOSTS + 1)
        .collect::<Vec<_>>();
    if targets.len() > MAX_DISCOVERY_HOSTS {
        return Err(DiscoveryError::TooManyHosts);
    }
    Ok(targets)
}

pub async fn ping_hosts(
    hosts: Vec<IpAddr>,
    semaphore: Arc<Semaphore>,
    max_concurrency: usize,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    let results = stream::iter(hosts)
        .map(|address| {
            let semaphore = Arc::clone(&semaphore);
            async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| DiscoveryError::SemaphoreClosed)?;
                let reachable = match tokio::time::timeout(ICMP_TIMEOUT, ping_one(address)).await {
                    Ok(Ok(())) => true,
                    Ok(Err(error)) => {
                        tracing::debug!(target = %address, error = %error, "ICMP discovery probe failed");
                        false
                    }
                    Err(_) => {
                        tracing::debug!(target = %address, "ICMP discovery probe timed out");
                        false
                    }
                };
                Ok(reachable.then_some(address))
            }
        })
        .buffer_unordered(max_concurrency.max(1))
        .collect::<Vec<Result<Option<IpAddr>, DiscoveryError>>>()
        .await;

    let mut reachable = Vec::new();
    for result in results {
        if let Some(address) = result? {
            reachable.push(address);
        }
    }
    reachable.sort_unstable();
    Ok(reachable)
}

async fn ping_one(address: IpAddr) -> Result<(), SurgeError> {
    let kind = match address {
        IpAddr::V4(_) => ICMP::V4,
        IpAddr::V6(_) => ICMP::V6,
    };
    let config = Config::builder().kind(kind).build();
    let client = Client::new(&config)?;
    let identifier = PingIdentifier(NEXT_PING_IDENTIFIER.fetch_add(1, Ordering::Relaxed));
    let mut pinger = client.pinger(address, identifier).await;
    pinger.timeout(ICMP_TIMEOUT);
    pinger.ping(PingSequence(0), b"nms-discovery").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ipnet::IpNet;

    use super::{DiscoveryError, is_allowed_subnet, targets_for_subnet};

    #[test]
    fn accepts_only_subnets_inside_configured_allowlist() -> Result<(), Box<dyn Error>> {
        let allowed: IpNet = "192.168.0.0/16".parse()?;
        let permitted: IpNet = "192.168.20.0/24".parse()?;
        let broader: IpNet = "192.168.0.0/15".parse()?;
        let other_family: IpNet = "fd00::/64".parse()?;

        assert!(is_allowed_subnet(&permitted, &[allowed]));
        assert!(!is_allowed_subnet(&broader, &[allowed]));
        assert!(!is_allowed_subnet(&other_family, &[allowed]));
        assert!(!is_allowed_subnet(&permitted, &[]));
        Ok(())
    }

    #[test]
    fn bounds_cidr_host_expansion() -> Result<(), Box<dyn Error>> {
        let small: IpNet = "192.0.2.0/24".parse()?;
        assert_eq!(targets_for_subnet(&small)?.len(), 254);

        let oversized: IpNet = "10.0.0.0/16".parse()?;
        assert!(matches!(
            targets_for_subnet(&oversized),
            Err(DiscoveryError::TooManyHosts)
        ));
        Ok(())
    }
}
