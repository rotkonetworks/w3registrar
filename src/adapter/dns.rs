use crate::{
    adapter::Adapter,
    api::{Account, Network, RedisConnection},
    config::GLOBAL_CONFIG,
};
use anyhow::Result;
use once_cell::sync::OnceCell;
use std::str::FromStr;
use std::sync::Arc;
use subxt::utils::AccountId32;
use tokio::time::{sleep, Duration};
use tracing::{error, info, instrument};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::rr::{RData, RecordType},
    AsyncResolver,
};

const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(30);

static DNS_RESOLVER: OnceCell<Arc<AsyncResolver<TokioConnectionProvider>>> = OnceCell::new();

fn get_resolver() -> Arc<AsyncResolver<TokioConnectionProvider>> {
    DNS_RESOLVER
        .get_or_init(|| {
            Arc::new(AsyncResolver::tokio(
                ResolverConfig::cloudflare_tls(),
                ResolverOpts::default(),
            ))
        })
        .clone()
}

#[instrument(skip_all)]
async fn lookup_txt_records(domain: &str) -> Result<Vec<String>, String> {
    info!(domain = %domain, "Looking for TXT records");
    get_resolver()
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

#[instrument(skip_all)]
pub async fn verify_txt(domain: &str, challenge: &str) -> bool {
    match lookup_txt_records(domain).await {
        Ok(records) => {
            for record in &records {
                info!(domain = %domain, "Found Record: {record}");
            }
            if records.contains(&challenge.to_string()) {
                info!(domain = %domain, "TXT record verification successful");
                return true;
            }
            info!(domain = %domain, "No matching({}) TXT record found", &challenge.to_string());
            false
        }
        Err(err) => {
            info!(domain = %domain, error = %err, "Record lookup failed");
            false
        }
    }
}

pub struct DnsAdapter;
impl Adapter for DnsAdapter {}

struct DnsChallenge {
    domain: String,
    network: Network,
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

        let network = Network::from_str(parts[2])?;
        let account_id = AccountId32::from_str(parts[3])?;

        let state = match redis_conn
            .get_verification_state(&network, &account_id)
            .await?
        {
            Some(s) => s,
            None => return Ok(None),
        };

        let token = match state.challenges.get(&crate::api::AccountType::Web) {
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

        let account = Account::Web(self.domain.clone());

        <DnsAdapter as Adapter>::handle_content(
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
pub async fn watch_dns() -> anyhow::Result<()> {
    // NOTE: is this ok?
    loop {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let mut redis_conn = RedisConnection::get_connection(&cfg.redis).await?;

        if let Err(e) = process_challenges(&mut redis_conn).await {
            error!("DNS challenge processing error: {}", e);
        }

        sleep(DNS_CHECK_INTERVAL).await;
    }
}

#[instrument(skip_all)]
async fn process_challenges(redis_conn: &mut RedisConnection) -> Result<()> {
    let challenge_keys = redis_conn.search("web|*").await?;

    for challenge_key in &challenge_keys {
        if let Err(e) = process_single_challenge(challenge_key, redis_conn).await {
            error!(challenge = %challenge_key, error = %e, "Challenge processing failed");
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
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

/// Function to be used for manual verification of DNS challenge instead of active watching
pub async fn _verify_dns_challenge(
    domain: &str,
    network: &Network,
    account_id: &AccountId32,
) -> Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let mut redis_conn = RedisConnection::get_connection(&cfg.redis).await?;

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

    let token = match state.challenges.get(&crate::api::AccountType::Web) {
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

    if verify_txt(&clean_domain, &token).await {
        let account = Account::Web(clean_domain);

        <DnsAdapter as Adapter>::handle_content(
            &token,
            &mut redis_conn,
            network,
            account_id,
            &account,
        )
        .await
    } else {
        Err(anyhow::anyhow!(
            "Unable to verify domain {} TXT record",
            domain
        ))
    }
}
