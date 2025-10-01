pub mod dns;
pub mod http;

use crate::{
    adapter::Adapter,
    api::{Account, AccountType, Network},
    redis::RedisConnection,
};
use anyhow::{anyhow, Result};
use std::str::FromStr;
use subxt::utils::AccountId32;
use tokio_stream::StreamExt;
use tracing::{error, info, instrument};

pub struct WebAdapter;
impl Adapter for WebAdapter {}

struct WebChallenge {
    domain: String,
    network: Network,
    account_id: AccountId32,
    token: String,
}

impl WebChallenge {
    async fn from_key(key: &str, redis_conn: &mut RedisConnection) -> Result<Option<Self>> {
        let parts: Vec<&str> = key.split('|').collect();
        if parts.len() != 4 {
            return Ok(None);
        }

        let domain = parts[1]
            .to_string()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();

        let network = Network::from_str(parts[2])?;
        let account_id = AccountId32::from_str(parts[3])?;

        let state = match redis_conn
            .get_verification_state(&network, &account_id)
            .await?
        {
            Some(s) => s,
            None => return Ok(None),
        };

        let token = match state.challenges.get(&AccountType::Web) {
            Some(challenge) if !challenge.done => match &challenge.token {
                Some(t) => t.clone(),
                None => return Ok(None),
            },
            _ => return Ok(None),
        };

        Ok(Some(Self {
            domain,
            network,
            account_id,
            token,
        }))
    }

    async fn verify(&self, redis_conn: &mut RedisConnection) -> Result<()> {
        // Try HTTP verification first (faster, no propagation delay)
        let http_verified = http::verify_http(&self.domain, &self.token).await;

        // If HTTP fails, try DNS verification
        let dns_verified = if !http_verified {
            info!(domain = %self.domain, "HTTP verification failed, trying DNS");
            dns::verify_txt(&self.domain, &self.token).await
        } else {
            false
        };

        if !http_verified && !dns_verified {
            info!(domain = %self.domain, "Both HTTP and DNS verification failed");
            return Ok(());
        }

        let verification_method = if http_verified { "HTTP" } else { "DNS" };
        info!(domain = %self.domain, method = %verification_method, "Domain verification successful");

        let account = Account::Web(self.domain.clone());

        <WebAdapter as Adapter>::handle_content(
            &self.token,
            redis_conn,
            &self.network,
            &self.account_id,
            &account,
        )
        .await?;

        Ok(())
    }
}

#[instrument()]
pub async fn watch_web() -> anyhow::Result<()> {
    info!("Web adapter watcher started (supports both HTTP and DNS verification)");
    let mut redis_conn = RedisConnection::get_connection().await?;

    let channel = format!("__keyspace@0__:web|*");

    if let Err(e) = redis_conn.subscribe(&channel).await {
        error!("Unable to subscribe to {} because {:?}", channel, e);
        return Err(anyhow!("Failed to subscribe to web channel"));
    };

    let mut stream = redis_conn.pubsub_stream().await;

    while let Some(msg) = stream.next().await {
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        if !matches!(payload.as_str(), "set") {
            continue;
        }

        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => continue,
        };

        let mut redis_conn = RedisConnection::get_connection().await?;

        let challenge_keys = redis_conn.search(key).await?;
        for challenge_key in &challenge_keys {
            if let Err(e) = process_single_challenge(challenge_key, &mut redis_conn).await {
                error!(challenge = %challenge_key, error = %e, "Challenge processing failed");
            }
        }
    }

    Ok(())
}

async fn process_single_challenge(
    challenge_key: &str,
    redis_conn: &mut RedisConnection,
) -> Result<()> {
    if let Some(challenge) = WebChallenge::from_key(challenge_key, redis_conn).await? {
        challenge.verify(redis_conn).await?;
    }
    Ok(())
}

/// Function to be used for manual verification of web challenge
/// Supports both HTTP and DNS verification methods
pub async fn verify_web_challenge(
    domain: &str,
    network: &Network,
    account_id: &AccountId32,
) -> Result<()> {
    let mut redis_conn = RedisConnection::get_connection().await?;

    let clean_domain = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();

    let state = match redis_conn
        .get_verification_state(network, account_id)
        .await?
    {
        Some(s) => s,
        None => {
            return Err(anyhow::anyhow!(
                "No verification state found for {account_id:?}/{domain}"
            ))
        }
    };

    let token = match state.challenges.get(&AccountType::Web) {
        Some(challenge) if !challenge.done => match &challenge.token {
            Some(t) => t.clone(),
            None => {
                return Err(anyhow::anyhow!(
                    "Unable to extract challenge for {account_id:?}/{domain}"
                ))
            }
        },
        _ => {
            return Err(anyhow::anyhow!(
                "No challenge is found for {account_id}/{domain}"
            ))
        }
    };

    // Try HTTP first, then DNS
    let http_verified = http::verify_http(&clean_domain, &token).await;
    let dns_verified = if !http_verified {
        dns::verify_txt(&clean_domain, &token).await
    } else {
        false
    };

    if http_verified || dns_verified {
        let verification_method = if http_verified { "HTTP" } else { "DNS" };
        info!(domain = %clean_domain, method = %verification_method, "Manual verification successful");

        let account = Account::Web(clean_domain.clone());

        <WebAdapter as Adapter>::handle_content(
            &token,
            &mut redis_conn,
            network,
            account_id,
            &account,
        )
        .await
    } else {
        Err(anyhow::anyhow!(
            "Unable to verify domain {} via HTTP or DNS",
            domain
        ))
    }
}

