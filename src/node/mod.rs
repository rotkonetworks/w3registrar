#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./metadata/people_paseo.scale")]
pub mod substrate {}

use crate::api::AccountType;
use crate::config::GLOBAL_CONFIG;

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use sp_core::Encode;
use std::collections::HashMap;
use std::str::FromStr;
use subxt::config::Header;
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tracing::info;

use super::api::Account;
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

/// Fetch current on-chain identity data
pub async fn get_registration(
    client: &Client,
    who: &AccountId32,
) -> Result<Registration<u128, IdentityInfo>> {
    let storage = client.storage().at_latest().await?;
    let identity = super::node::storage().identity().identity_of(who);
    info!("identity: {:?}", identity);
    match storage.fetch(&identity).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}

/// Setup client and load network configuration
async fn setup_network(network: &str) -> anyhow::Result<(Client, crate::config::RegistrarConfig)> {
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

pub async fn provide_judgement<'a>(
    who: &AccountId32,
    judgement: Judgement<u128>,
    network: &str,
) -> anyhow::Result<&'a str> {
    let (client, network_cfg) = setup_network(network).await?;

    info!("Using registrar index: {}", network_cfg.registrar_index);

    let registration = get_registration(&client, who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));
    info!("Generated identity hash: {}", hash);

    // Create the inner identity call
    let inner_call = substrate::runtime_types::pallet_identity::pallet::Call::provide_judgement {
        reg_index: network_cfg.registrar_index,
        target: subxt::utils::MultiAddress::Id(who.clone()),
        judgement,
        identity: Identity::from_str(&hash)?,
    };

    // Wrap in proxy call
    let tx = substrate::tx().proxy().proxy(
        subxt::utils::MultiAddress::Id(AccountId32::from_str(&network_cfg.registrar_account)?),
        Some(ProxyType::IdentityJudgement),
        RuntimeCall::Identity(inner_call),
    );

    // Load proxy account only when we need to sign
    let signer = {
        info!("Reading keystore from: {}", network_cfg.keystore_path);
        let seed = std::fs::read_to_string(&network_cfg.keystore_path).map_err(|e| {
            anyhow!(
                "Failed to read keystore at {}: {}",
                network_cfg.keystore_path,
                e
            )
        })?;
        info!("Creating signer from seed");
        let acc = Sr25519Pair::from_string(&seed.trim(), None)?;
        let signer = PairSigner::new(acc);
        let ss58_address = signer.account_id().to_string();
        info!(
            "Signer account (just default hex, not index0): {}",
            ss58_address
        );
        info!("Signer account (raw): {:?}", signer.account_id());

        signer
    };

    // Get latest block for mortality calculation
    let latest_block = client.blocks().at_latest().await?;
    info!("Latest block: {:?}", latest_block.header().hash());

    // Build transaction parameters with explicit SubstrateConfig
    //let tx_params = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::<SubstrateConfig>::new()
    //    .tip(0)
    //    .mortal(latest_block.header(), 100) // Set mortality to 100 blocks
    //    .build();

    info!("Submitting transaction...");

    // Submit and watch transaction
    let mut tx_progress = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, &signer)
        .await?;

    while let Some(status) = tx_progress.next().await {
        match status? {
            subxt::tx::TxStatus::InFinalizedBlock(in_block) => {
                info!(
                    "Transaction {:?} is finalized in block {:?}",
                    in_block.extrinsic_hash(),
                    in_block.block_hash()
                );

                // Wait for success and get events
                let events = in_block.wait_for_success().await?;
                info!("Transaction successful: {:?}", events);
                return Ok("Judgment submitted through proxy");
            }
            other => {
                info!("Transaction status: {:?}", other);
            }
        }
    }

    Err(anyhow!("Transaction failed to finalize"))
}

/// Maintain backward compatibility
pub async fn register_identity<'a>(
    who: &AccountId32,
    _reg_index: u32,
    network: &str,
) -> anyhow::Result<&'a str> {
    provide_judgement(who, Judgement::Reasonable, network).await
}

/// Filter accounts based on supported fields and provide appropriate judgment
pub async fn filter_accounts(
    info: &IdentityInfo,
    who: &AccountId32,
    _reg_index: u32,
    network: &str,
) -> anyhow::Result<HashMap<Account, bool>> {
    let accounts = Account::into_accounts(info);
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    let supported = &network_cfg.fields;

    if accounts.is_empty() {
        provide_judgement(who, Judgement::Unknown, network).await?;
        return Ok(HashMap::new());
    }

    for account in &accounts {
        let account_type = account.account_type();
        if !supported
            .iter()
            .any(|s| AccountType::from_str(s).ok() == Some(account_type))
        {
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
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .init();

        info!("Starting judgment test");
        init_config().await;

        let target_account =
            AccountId32::from_str("1Qrotkokp6taAeLThuwgzR7Mu3YQonZohwrzixwGnrD1QDT")?;
        info!("Target account: {:?}", target_account);

        let (client, network_cfg) = setup_network("paseo").await?;
        info!(
            "Network config loaded: endpoint={}, registrar_index={}",
            network_cfg.endpoint, network_cfg.registrar_index
        );

        match get_registration(&client, &target_account).await {
            Ok(reg) => info!("Found registration: {:?}", reg),
            Err(e) => warn!("Registration check failed: {}", e),
        }

        let result = provide_judgement(&target_account, Judgement::Reasonable, "paseo").await?;

        info!("Judgment result: {}", result);
        assert_eq!(result, "Judgment submitted through proxy");
        Ok(())
    }
}
