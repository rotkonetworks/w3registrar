use crate::{api::RedisConnection, config::GLOBAL_CONFIG, node::register_identity};
use anyhow::Result;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::rr::{RData, RecordType},
    AsyncResolver,
};

const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(30);

async fn lookup_txt_records(
    domain: &str,
    resolver: &AsyncResolver<TokioConnectionProvider>,
) -> Result<Vec<String>, String> {
    resolver
        .lookup(domain, RecordType::TXT)
        .await
        .map(|response| {
            response
                .iter()
                .filter_map(|record| match record {
                    RData::TXT(txt_data) => Some(txt_data),
                    _ => None,
                })
                .flat_map(|txt_data| txt_data.iter())
                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                .collect()
        })
        .map_err(|e| e.to_string())
}

pub async fn verify_txt(domain: &str, challenge: &str) -> bool {
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    match lookup_txt_records(domain, &resolver).await {
        Ok(records) => {
            for record in &records {
                info!("Found {}:{}:{}", domain, challenge, record);
            }
            if records.contains(&challenge.to_string()) {
                info!("TXT record verification successful for {}", domain);
                return true;
            }
            info!("No matching({}) TXT record found", &challenge.to_string());
            false
        }
        Err(err) => {
            info!("Lookup failed for {}: {}", domain, err);
            false
        }
    }
}

struct DnsChallenge {
    domain: String,
    network: String,
    account_id: AccountId32,
    token: String,
}

impl DnsChallenge {
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

        let network = parts[2].to_string();
        let account_id = AccountId32::from_str(parts[3])?;

        let state = match redis_conn
            .get_verification_state(&network, &account_id)
            .await?
        {
            Some(s) => s,
            None => return Ok(None),
        };

        let token = match state.challenges.get("web") {
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
        if !verify_txt(&self.domain, &self.token).await {
            return Ok(());
        }

        redis_conn
            .update_challenge_status(&self.network, &self.account_id, "web")
            .await?;
        self.check_completion(redis_conn).await
    }

    async fn check_completion(&self, redis_conn: &mut RedisConnection) -> Result<()> {
        if let Some(state) = redis_conn
            .get_verification_state(&self.network, &self.account_id)
            .await?
        {
            if state.all_done {
                register_identity(&self.account_id, &self.network).await?;
            }
        }
        Ok(())
    }
}

pub async fn watch_dns() -> Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let mut redis_conn = RedisConnection::create_conn(&cfg.redis)?;

    loop {
        if let Err(e) = process_challenges(&mut redis_conn).await {
            error!("DNS challenge processing error: {}", e);
        }
        sleep(DNS_CHECK_INTERVAL).await;
    }
}

async fn process_challenges(redis_conn: &mut RedisConnection) -> Result<()> {
    for challenge_key in redis_conn.search("web|*")? {
        if let Err(e) = process_single_challenge(&challenge_key, redis_conn).await {
            error!("Challenge processing failed {}: {}", challenge_key, e);
        }
    }
    Ok(())
}

async fn process_single_challenge(
    challenge_key: &str,
    redis_conn: &mut RedisConnection,
) -> Result<()> {
    if let Some(challenge) = DnsChallenge::from_key(challenge_key, redis_conn).await? {
        challenge.verify(redis_conn).await?;
    }
    Ok(())
}
