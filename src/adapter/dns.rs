use hickory_resolver::{AsyncResolver, config::{ResolverConfig, ResolverOpts}};
use hickory_resolver::proto::rr::{RecordType, RData};
use crate::{
    api::RedisConnection,
    config::GLOBAL_CONFIG,
    node::register_identity,
};
use anyhow::Result;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

/// Time between DNS verification attempts
const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Verifies the presence of a TXT record in a domain's DNS entries
pub async fn verify_txt(domain: &str, txt: &str) -> bool {
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    
    let lookup_result = match resolver.lookup(domain, RecordType::TXT).await {
        Ok(response) => response,
        Err(e) => {
            error!("DNS lookup failed for domain {}: {}", domain, e);
            return false;
        }
    };

    lookup_result
        .iter()
        .filter_map(|record| match record {
            RData::TXT(txt_data) => Some(txt_data),
            _ => None,
        })
        .flat_map(|txt_data| txt_data.iter())
        .map(|bytes| String::from_utf8_lossy(bytes))
        .any(|record| record == txt)
}

struct DnsChallenge {
    domain: String,
    network: String,
    account_id: AccountId32,
    token: String,
}

impl DnsChallenge {
    async fn from_key(key: &str) -> Result<Option<(Self, RedisConnection)>> {
        let cfg = GLOBAL_CONFIG.get().expect("GLOBAL_CONFIG is not initialized");
        let mut redis_conn = RedisConnection::create_conn(&cfg.redis)?;

        let parts: Vec<&str> = key.split('|').collect();
        if parts.len() != 4 {
            return Ok(None);
        }

        let domain = parts[1].to_string();
        let network = parts[2].to_string();
        let account_id = AccountId32::from_str(parts[3])?;

        let state = match redis_conn.get_verification_state(&network, &account_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let token = match state.challenges.get("web") {
            Some(challenge) if !challenge.done => {
                match &challenge.token {
                    Some(t) => t.clone(),
                    None => return Ok(None),
                }
            },
            _ => return Ok(None),
        };

        Ok(Some((Self {
            domain,
            network,
            account_id,
            token,
        }, redis_conn)))
    }

    async fn verify(&self, redis_conn: &mut RedisConnection) -> Result<()> {
        if !verify_txt(&self.domain, &self.token).await {
            return Ok(());
        }

        info!("DNS verification successful for {}", self.domain);
        redis_conn.update_challenge_status(&self.network, &self.account_id, "web").await?;

        self.check_completion(redis_conn).await
    }

    async fn check_completion(&self, redis_conn: &mut RedisConnection) -> Result<()> {
        let state = redis_conn.get_verification_state(&self.network, &self.account_id).await?;
        
        match state {
            Some(state) if state.all_done => {
                info!("All challenges completed for {}", self.account_id);
                register_identity(&self.account_id, &self.network).await?;
            },
            _ => (),
        }

        Ok(())
    }
}

pub async fn watch_dns() -> Result<()> {
    info!("Starting DNS watcher service...");
    
    loop {
        if let Err(e) = process_challenges().await {
            error!("Error processing challenges: {}", e);
        }
        sleep(DNS_CHECK_INTERVAL).await;
    }
}

async fn process_challenges() -> Result<()> {
    let cfg = GLOBAL_CONFIG.get().expect("GLOBAL_CONFIG is not initialized");
    let mut redis_conn = RedisConnection::create_conn(&cfg.redis)?;

    let web_challenges = redis_conn.search("web|*")?;

    for challenge_key in web_challenges {
        if let Err(e) = process_single_challenge(&challenge_key).await {
            error!("Failed to process challenge {}: {}", challenge_key, e);
        }
    }

    Ok(())
}

async fn process_single_challenge(challenge_key: &str) -> Result<()> {
    info!("Processing web challenge: {}", challenge_key);
    
    let (challenge, mut redis_conn) = match DnsChallenge::from_key(challenge_key).await? {
        Some(data) => data,
        None => return Ok(()),
    };

    challenge.verify(&mut redis_conn).await
}
