#![allow(dead_code)]

pub mod chains;
pub mod events;
pub mod listener;

use crate::api::{AccountType, Network};
use crate::config::Config;

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};
use subxt::tx::Signer;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;
use tracing::{error, info, warn};

use super::api::Account;
use super::redis::RedisConnection;

pub type Client = subxt::OnlineClient<SubstrateConfig>;
pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
pub type BlockHash = subxt::config::substrate::H256;
type PairSigner = Keypair;


// Re-export common identity types from paseo (they're structurally identical)
pub use chains::paseo::runtime as substrate;
pub use chains::paseo::runtime::identity;
pub use chains::paseo::runtime::runtime_types;

// consts
const MAX_RESUBMIT_ATTEMPTS: u32 = 3;
const FINALIZATION_TIMEOUT: Duration = Duration::from_secs(180);
const BASE_DELAY: Duration = Duration::from_secs(1);

/// Setup client and load network configuration
async fn setup_network(
    network: &Network,
) -> anyhow::Result<(Client, crate::config::RegistrarConfig)> {
    let cfg = Config::load_static();

    let network_cfg = cfg.registrar.require_network(network)?;

    let client = Client::from_url(&network_cfg.endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} network({}) because of {}",
            network,
            network_cfg.endpoint,
            e,
        )
    })?;

    Ok((client, network_cfg.clone()))
}

/// Load signer from keystore path
fn load_signer(network_cfg: &crate::config::RegistrarConfig) -> Result<PairSigner> {
    info!("Reading keystore from: {}", network_cfg.keystore_path);
    let seed = std::fs::read_to_string(&network_cfg.keystore_path)
        .map_err(|e| anyhow!("Failed to read keystore: {}", e))?;

    let uri = SecretUri::from_str(seed.trim())?;
    let signer = Keypair::from_uri(&uri)?;

    info!(
        account_id = &<Keypair as Signer<SubstrateConfig>>::account_id(&signer).to_string(),
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

/// Macro to implement chain-specific operations
/// Each chain has different runtime types but identical identity pallet
macro_rules! impl_chain_ops {
    ($mod_name:ident, $chain:ident, $network_variant:ident) => {
        pub mod $mod_name {
            use super::*;
            use crate::node::chains::$chain::{IdentityInfo, Judgement, ProxyType, Registration, RuntimeCall};
            use crate::node::chains::$chain::runtime;

            pub type ChainIdentityInfo = IdentityInfo;

            /// Fetch current on-chain identity data
            pub async fn get_registration(
                client: &Client,
                who: &AccountId32,
            ) -> Result<Registration<u128, IdentityInfo>> {
                let storage = client.storage().at_latest().await?;
                let identity = runtime::storage().identity().identity_of(who.clone());
                match storage.fetch(&identity).await? {
                    None => Err(anyhow!("No registration found for {}", who)),
                    Some(reg) => Ok(reg),
                }
            }

            pub async fn get_judgement(
                who: &AccountId32,
            ) -> Result<Option<Judgement<u128>>> {
                let (client, _) = setup_network(&Network::$network_variant).await?;
                match get_registration(&client, who).await {
                    Ok(mut registration) => Ok(registration.judgements.0.pop().map(|(_, j)| j)),
                    Err(_) => Ok(None),
                }
            }

            /// Handles transaction submission with retries and error handling
            pub async fn provide_judgement<'a>(
                who: &AccountId32,
                judgement: Judgement<u128>,
            ) -> Result<&'a str> {
                let network = Network::$network_variant;
                info!(
                    account_id = %who.to_string(),
                    network = %network,
                    judgement = %format!("{:?}", judgement),
                    "Providing judgment"
                );
                let (client, network_cfg) = setup_network(&network).await?;

                let registration = get_registration(&client, who).await?;
                let hash = hex::encode(blake2_256(&parity_scale_codec::Encode::encode(&registration.info)));

                info!(
                    hash = %hash,
                    reg_index = %network_cfg.registrar_index,
                    endpoint = %network_cfg.endpoint,
                    "Generated identity hash"
                );

                use runtime::identity::calls::types::provide_judgement::Identity;
                let inner_call = runtime::runtime_types::pallet_identity::pallet::Call::provide_judgement {
                    reg_index: network_cfg.registrar_index,
                    target: subxt::utils::MultiAddress::Id(who.clone()),
                    judgement,
                    identity: Identity::from_str(&hash)?,
                };

                let tx = runtime::tx().proxy().proxy(
                    subxt::utils::MultiAddress::Id(AccountId32::from_str(&network_cfg.registrar_account)?),
                    Some(ProxyType::IdentityJudgement),
                    RuntimeCall::Identity(inner_call),
                );
                info!("Proxy connected!");

                let signer = load_signer(&network_cfg)?;
                info!("Signer loaded");
                let mut resubmit_count = 0;
                let mut current_fee_multiplier = 1.0;
                let mut current_nonce = client.tx().account_nonce(&<Keypair as Signer<SubstrateConfig>>::account_id(&signer)).await?;
                info!("Nonce fetched");

                'tx_loop: while resubmit_count < MAX_RESUBMIT_ATTEMPTS {
                    let start_time = Instant::now();
                    let latest_block = client.blocks().at_latest().await?;
                    info!(block_hash=?hex::encode(latest_block.hash().0), "Latest block");

                    let tx_params = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new()
                        .mortal(10)
                        .nonce(current_nonce)
                        .tip((100_000_f64 * current_fee_multiplier) as u128)
                        .build();

                    let mut tx_progress = client
                        .tx()
                        .sign_and_submit_then_watch(&tx, &signer, tx_params)
                        .await?;
                    info!("Watching transactions");

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
                                current_fee_multiplier *= 1.2;
                                info!(
                                    "Transaction no longer in best block, bumping fee multiplier to {}, attempting resubmission {}/{}",
                                    current_fee_multiplier,
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
                                    current_nonce = fetch_latest_nonce(&client, &<Keypair as Signer<SubstrateConfig>>::account_id(&signer)).await?;
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
                            subxt::tx::TxStatus::Broadcasted => {
                                info!("Transaction broadcasted");
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

            /// Provides successful judgement
            pub async fn register_identity<'a>(
                who: &AccountId32,
            ) -> anyhow::Result<&'a str> {
                let reg_state = provide_judgement(who, Judgement::Reasonable).await;

                let mut redis_conn = RedisConnection::default().await?;
                redis_conn.clear_all_related_to(&Network::$network_variant, who).await?;

                reg_state
            }

            /// Filter accounts based on supported fields
            pub async fn filter_accounts(
                info: &IdentityInfo,
                who: &AccountId32,
                _reg_index: u32,
            ) -> anyhow::Result<HashMap<Account, bool>> {
                let network = Network::$network_variant;
                info!(account_id = %who.to_string(), "Filtering unsupported accounts");

                // Transmute to paseo type since they're structurally identical
                let paseo_info: &chains::paseo::IdentityInfo = unsafe { std::mem::transmute(info) };
                let accounts = Account::into_accounts(paseo_info);
                info!(accounts=?accounts,"Found accounts");

                let cfg = Config::load_static();
                let network_cfg = cfg.registrar.require_network(&network)?;

                let supported = &network_cfg.fields;
                info!(fields=?supported, network=?network,"Supported fields for requested network");

                if accounts.is_empty() {
                    info!("No accounts found, providing Unknown judgment");
                    provide_judgement(who, Judgement::Unknown).await?;
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
                        provide_judgement(who, Judgement::Erroneous).await?;
                        return Ok(HashMap::new());
                    }
                }

                Ok(Account::into_hashmap(accounts, false))
            }
        }
    };
}

// Generate chain-specific modules
impl_chain_ops!(polkadot_ops, polkadot, Polkadot);
impl_chain_ops!(kusama_ops, kusama, Kusama);
impl_chain_ops!(paseo_ops, paseo, Paseo);

// Unified API that dispatches to the correct chain implementation

/// Fetch current on-chain identity data for any network
pub async fn get_registration_for_network(
    client: &Client,
    who: &AccountId32,
    network: &Network,
) -> Result<chains::paseo::Registration<u128, chains::paseo::IdentityInfo>> {
    // All chains use structurally identical Registration types
    // We use paseo as the canonical type
    match network {
        Network::Polkadot => {
            let reg = polkadot_ops::get_registration(client, who).await?;
            // Safe transmute - types are structurally identical
            Ok(unsafe { std::mem::transmute(reg) })
        }
        Network::Kusama => {
            let reg = kusama_ops::get_registration(client, who).await?;
            Ok(unsafe { std::mem::transmute(reg) })
        }
        Network::Paseo => paseo_ops::get_registration(client, who).await,
        Network::Rococo => Err(anyhow!("Rococo People chain not yet supported")),
    }
}

/// Get judgement for any network
pub async fn get_judgement(
    who: &AccountId32,
    network: &Network,
) -> Result<Option<chains::paseo::Judgement<u128>>> {
    match network {
        Network::Polkadot => {
            let j = polkadot_ops::get_judgement(who).await?;
            Ok(j.map(|j| unsafe { std::mem::transmute(j) }))
        }
        Network::Kusama => {
            let j = kusama_ops::get_judgement(who).await?;
            Ok(j.map(|j| unsafe { std::mem::transmute(j) }))
        }
        Network::Paseo => paseo_ops::get_judgement(who).await,
        Network::Rococo => Err(anyhow!("Rococo People chain not yet supported")),
    }
}

/// Provide judgement for any network
pub async fn provide_judgement<'a>(
    who: &AccountId32,
    judgement: chains::paseo::Judgement<u128>,
    network: &Network,
) -> Result<&'a str> {
    match network {
        Network::Polkadot => {
            let j: chains::polkadot::Judgement<u128> = unsafe { std::mem::transmute(judgement) };
            polkadot_ops::provide_judgement(who, j).await
        }
        Network::Kusama => {
            let j: chains::kusama::Judgement<u128> = unsafe { std::mem::transmute(judgement) };
            kusama_ops::provide_judgement(who, j).await
        }
        Network::Paseo => paseo_ops::provide_judgement(who, judgement).await,
        Network::Rococo => Err(anyhow!("Rococo People chain not yet supported")),
    }
}

/// Register identity for any network
pub async fn register_identity<'a>(
    who: &AccountId32,
    network: &Network,
) -> anyhow::Result<&'a str> {
    match network {
        Network::Polkadot => polkadot_ops::register_identity(who).await,
        Network::Kusama => kusama_ops::register_identity(who).await,
        Network::Paseo => paseo_ops::register_identity(who).await,
        Network::Rococo => Err(anyhow!("Rococo People chain not yet supported")),
    }
}

/// Filter accounts for any network
pub async fn filter_accounts(
    info: &chains::paseo::IdentityInfo,
    who: &AccountId32,
    reg_index: u32,
    network: &Network,
) -> anyhow::Result<HashMap<Account, bool>> {
    match network {
        Network::Polkadot => {
            let i: &chains::polkadot::IdentityInfo = unsafe { std::mem::transmute(info) };
            polkadot_ops::filter_accounts(i, who, reg_index).await
        }
        Network::Kusama => {
            let i: &chains::kusama::IdentityInfo = unsafe { std::mem::transmute(info) };
            kusama_ops::filter_accounts(i, who, reg_index).await
        }
        Network::Paseo => paseo_ops::filter_accounts(info, who, reg_index).await,
        Network::Rococo => Err(anyhow!("Rococo People chain not yet supported")),
    }
}

/// Convenience alias for backwards compatibility
pub async fn get_registration(
    client: &Client,
    who: &AccountId32,
) -> Result<chains::paseo::Registration<u128, chains::paseo::IdentityInfo>> {
    paseo_ops::get_registration(client, who).await
}

/// Default chain registrar using the actual on-chain registration
pub struct DefaultChainRegistrar;

#[async_trait::async_trait]
impl crate::adapter::context::ChainRegistrar for DefaultChainRegistrar {
    async fn register_identity(
        &self,
        account_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()> {
        register_identity(account_id, network).await?;
        Ok(())
    }
}

// Re-export storage/tx accessors
pub fn storage() -> chains::paseo::runtime::StorageApi {
    chains::paseo::runtime::storage()
}

pub fn tx() -> chains::paseo::runtime::TransactionApi {
    chains::paseo::runtime::tx()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Once;
    use tracing::info;

    static INIT: Once = Once::new();

    async fn init_config() {
        INIT.call_once(|| {
            let config =
                Config::load_from("config.toml").expect("Failed to load config from config.toml");
            info!("Loaded config: {:?}", config);
            Config::load_cell()
                .set(config)
                .expect("Failed to set global config");
        });
    }

    #[tokio::test]
    async fn test_network_setup() {
        init_config().await;

        // Test that we can set up each network
        for network in [Network::Paseo, Network::Polkadot, Network::Kusama] {
            let result = setup_network(&network).await;
            // May fail if network not configured, but shouldn't panic
            if let Err(e) = result {
                println!("Network {} not configured: {}", network, e);
            }
        }
    }
}
