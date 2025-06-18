#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./metadata/people_paseo.scale")]
pub mod substrate {}

use crate::api::{AccountType, Network};
use crate::config::GLOBAL_CONFIG;

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use sp_core::Encode;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tracing::{error, info, warn};

use super::api::Account;
use super::api::RedisConnection;
use substrate::identity::calls::types::provide_judgement::Identity;
use substrate::runtime_types::pallet_identity::types::Judgement;
use substrate::runtime_types::pallet_identity::types::Registration;
use substrate::runtime_types::people_paseo_runtime::people::IdentityInfo;
use substrate::runtime_types::people_paseo_runtime::ProxyType;
use substrate::runtime_types::people_paseo_runtime::RuntimeCall;

pub use substrate::*;
pub type Client = subxt::OnlineClient<SubstrateConfig>;
pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;
type PairSigner = subxt::tx::PairSigner<SubstrateConfig, Sr25519Pair>;

// consts
const MAX_RESUBMIT_ATTEMPTS: u32 = 3;
const FINALIZATION_TIMEOUT: Duration = Duration::from_secs(180);
const BASE_DELAY: Duration = Duration::from_secs(1);

/// Fetch current on-chain identity data
pub async fn get_registration(
    client: &Client,
    who: &AccountId32,
) -> Result<Registration<u128, IdentityInfo>> {
    let storage = client.storage().at_latest().await?;
    let identity = super::node::storage().identity().identity_of(who);
    match storage.fetch(&identity).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some(reg) => Ok(reg),
    }
}

/// Setup client and load network configuration
///
/// # Arguments
/// * `network` - Network name (network_name)
async fn setup_network(
    network: &Network,
) -> anyhow::Result<(Client, crate::config::RegistrarConfig)> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    let client = Client::from_url(&network_cfg.endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} network({}) because of {}",
            network,
            network_cfg.endpoint,
            e.to_string(),
        )
    })?;

    Ok((client, network_cfg.clone()))
}

/// Handles transaction submission with retries and error handling
pub async fn provide_judgement<'a>(
    who: &AccountId32,
    judgement: Judgement<u128>,
    network: &Network,
) -> Result<&'a str> {
    info!(
        account_id = %who.to_string(),
        network = %network,
        judgement = %format!("{:?}", judgement),
        "Providing judgment"
    );
    let (client, network_cfg) = setup_network(network).await?;

    let registration = get_registration(&client, who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    info!(
        hash = %hash,
        reg_index = %network_cfg.registrar_index,
        endpoint = %network_cfg.endpoint,
        "Generated identity hash"
    );

    let inner_call = substrate::runtime_types::pallet_identity::pallet::Call::provide_judgement {
        reg_index: network_cfg.registrar_index,
        target: subxt::utils::MultiAddress::Id(who.clone()),
        judgement,
        identity: Identity::from_str(&hash)?,
    };

    let tx = substrate::tx().proxy().proxy(
        subxt::utils::MultiAddress::Id(AccountId32::from_str(&network_cfg.registrar_account)?),
        Some(ProxyType::IdentityJudgement),
        RuntimeCall::Identity(inner_call),
    );

    let signer = load_signer(&network_cfg)?;
    let mut resubmit_count = 0;
    let mut current_fee_multiplier = 1.0;
    let mut current_nonce = client.tx().account_nonce(signer.account_id()).await?;

    'tx_loop: while resubmit_count < MAX_RESUBMIT_ATTEMPTS {
        let start_time = Instant::now();
        let latest_block = client.blocks().at_latest().await?;

        // build transaction params with current nonce
        let tx_params = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new()
            .mortal(latest_block.header(), 10)
            .nonce(current_nonce)
            .tip((100_000_f64 * current_fee_multiplier) as u128)
            .build();

        // submit and watch transaction
        let mut tx_progress = client
            .tx()
            .sign_and_submit_then_watch(&tx, &signer, tx_params)
            .await?;

        while let Some(status) = tx_progress.next().await {
            if start_time.elapsed() > FINALIZATION_TIMEOUT {
                warn!("Transaction timed out waiting for finalization");
                resubmit_count += 1;
                tokio::time::sleep(exponential_backoff(resubmit_count)).await;
                continue 'tx_loop;
            }

            match status? {
                subxt::tx::TxStatus::InFinalizedBlock(in_block) => {
                    info!(transaction=?in_block.extrinsic_hash(), block=?in_block.block_hash(),
                        "Transaction is finalized",
                    );

                    match in_block.wait_for_success().await {
                        Ok(events) => {
                            info!("Transaction successful: {:?}", events);
                            return Ok("Judgment submitted through proxy");
                        }
                        Err(e) if e.to_string().contains("out of gas") => {
                            warn!("Transaction failed due to out of gas: {}", e);
                            return Err(anyhow!("Transaction failed: insufficient gas"));
                        }
                        Err(e) => {
                            warn!("Transaction failed in block: {}", e);
                            return Err(anyhow!("Transaction failed in block: {}", e));
                        }
                    }
                }
                subxt::tx::TxStatus::NoLongerInBestBlock => {
                    info!(
                        "Transaction no longer in best block, attempting resubmission {}/{}",
                        resubmit_count + 1,
                        MAX_RESUBMIT_ATTEMPTS
                    );
                    resubmit_count += 1;
                    tokio::time::sleep(exponential_backoff(resubmit_count)).await;
                    continue 'tx_loop;
                }
                subxt::tx::TxStatus::Error { message } => {
                    if message.contains("nonce") {
                        warn!("Nonce error detected, fetching latest nonce");
                        current_nonce = fetch_latest_nonce(&client, signer.account_id()).await?;
                        resubmit_count += 1;
                        tokio::time::sleep(exponential_backoff(resubmit_count)).await;
                        continue 'tx_loop;
                    }
                    return Err(anyhow!("Transaction failed with error: {}", message));
                }
                subxt::tx::TxStatus::Invalid { message } => {
                    return Err(anyhow!("Transaction is invalid: {}", message));
                }
                subxt::tx::TxStatus::Dropped { message } => {
                    if message.contains("low priority") || message.contains("fee too low") {
                        warn!(
                            "Transaction dropped due to low fee, increasing fee multiplier to {}",
                            current_fee_multiplier * 1.5
                        );
                        current_fee_multiplier *= 1.5;
                        resubmit_count += 1;
                        tokio::time::sleep(exponential_backoff(resubmit_count)).await;
                        continue 'tx_loop;
                    }
                    return Err(anyhow!("Transaction was dropped: {}", message));
                }
                subxt::tx::TxStatus::Validated => {
                    info!("Transaction validated and added to the pool");
                }
                subxt::tx::TxStatus::Broadcasted { num_peers } => {
                    info!("Transaction broadcasted to {} peers", num_peers);
                }
                subxt::tx::TxStatus::InBestBlock(in_block) => {
                    info!(
                        "Transaction {:?} included in block {:?}",
                        in_block.extrinsic_hash(),
                        in_block.block_hash()
                    );
                }
            }
        }
    }

    Err(anyhow!(
        "Transaction failed to finalize after {} attempts",
        MAX_RESUBMIT_ATTEMPTS
    ))
}

/// Load signer from keystore path
fn load_signer(network_cfg: &crate::config::RegistrarConfig) -> Result<PairSigner> {
    info!("Reading keystore from: {}", network_cfg.keystore_path);
    let seed = std::fs::read_to_string(&network_cfg.keystore_path)
        .map_err(|e| anyhow!("Failed to read keystore: {}", e))?;

    let acc = Sr25519Pair::from_string(seed.trim(), None)?;
    let signer = PairSigner::new(acc);

    info!(
        account_id = &signer.account_id().to_string(),
        "Signer account"
    );
    Ok(signer)
}

/// Calculate exponential backoff delay
fn exponential_backoff(attempt: u32) -> Duration {
    BASE_DELAY * 2u32.pow(attempt - 1)
}

/// Fetch the latest nonce for an account
async fn fetch_latest_nonce(client: &Client, account: &AccountId32) -> Result<u64> {
    client
        .tx()
        .account_nonce(account)
        .await
        .map_err(|e| anyhow!("Failed to fetch nonce: {}", e))
}

/// Provides successful judgement
pub async fn register_identity<'a>(
    who: &AccountId32,
    network: &Network,
) -> anyhow::Result<&'a str> {
    let reg_state = provide_judgement(who, Judgement::Reasonable, network).await;
    
    // Clear only this user's verification data instead of all caches
    let mut redis_conn = RedisConnection::default().await?;
    redis_conn.clear_all_related_to(network, who).await?;
    
    reg_state
}

/// Filter accounts based on supported fields and provide appropriate judgment
pub async fn filter_accounts(
    info: &IdentityInfo,
    who: &AccountId32,
    _reg_index: u32,
    network: &Network,
) -> anyhow::Result<HashMap<Account, bool>> {
    info!(account_id = %who.to_string(), "Filtering unsupported accounts");

    let accounts = Account::into_accounts(info);
    info!(accounts=?accounts,"Found accounts");

    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    let supported = &network_cfg.fields;
    info!(fields=?supported, network=?network,"Supported fields for requested network");

    if accounts.is_empty() {
        info!("No accounts found, providing Unknown judgment");
        provide_judgement(who, Judgement::Unknown, network).await?;
        return Ok(HashMap::new());
    }

    for account in &accounts {
        let account_type = account.account_type();
        info!(account_type = %account_type, "Checking account type");
        if !supported
            .iter()
            .any(|s| AccountType::from_str(s).ok() == Some(account_type))
        {
            error!(account_type=?account_type, "Unsupported account type");
            provide_judgement(who, Judgement::Erroneous, network).await?;
            return Ok(HashMap::new());
        }
    }

    Ok(Account::into_hashmap(accounts, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, GLOBAL_CONFIG};
    use std::sync::Once;
    use tracing::{info, warn};

    static INIT: Once = Once::new();

    async fn init_config() {
        INIT.call_once(|| {
            let config =
                Config::load_from("config.toml").expect("Failed to load config from config.toml");
            info!("Loaded config: {:?}", config);
            GLOBAL_CONFIG
                .set(config)
                .expect("Failed to set global config");
        });
    }

    #[tokio::test]
    async fn test_provide_judgement_via_proxy() -> anyhow::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .init();

        info!("Starting judgment test");
        init_config().await;

        let target_account =
            AccountId32::from_str("1Qrotkokp6taAeLThuwgzR7Mu3YQonZohwrzixwGnrD1QDT")?;
        info!(target_account = %target_account.to_string(), "Target account");

        let (client, network_cfg) = setup_network(&Network::Paseo).await?;
        info!(
            "Network config loaded: endpoint={}, registrar_index={}",
            network_cfg.endpoint, network_cfg.registrar_index
        );

        match get_registration(&client, &target_account).await {
            Ok(reg) => info!("Found registration: {:?}", reg),
            Err(e) => warn!("Registration check failed: {}", e),
        }

        let result =
            provide_judgement(&target_account, Judgement::Reasonable, &Network::Paseo).await?;

        info!("Judgment result: {}", result);
        assert_eq!(result, "Judgment submitted through proxy");
        Ok(())
    }
}
