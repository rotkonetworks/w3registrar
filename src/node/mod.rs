#![allow(dead_code)]

// TODO: own mod for each network because lets say paseo updates it will break polkadot
#[subxt::subxt(runtime_metadata_path = "./metadata/people_paseo.scale")]
pub mod substrate {}

use crate::api::AccountType;
use crate::config::GLOBAL_CONFIG;

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use sp_core::Encode;
use std::collections::HashMap;
use std::str::FromStr;
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

pub use substrate::*;
pub type Client = subxt::OnlineClient<SubstrateConfig>;
pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;
type PairSigner = subxt::tx::PairSigner<SubstrateConfig, Sr25519Pair>;

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

pub async fn provide_judgement<'a>(
    who: &AccountId32,
    reg_index: u32,
    judgement: Judgement<u128>,
    endpoint: &str,
) -> anyhow::Result<&'a str> {
    let client = Client::from_url(endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} because of {}",
            endpoint,
            e.to_string()
        )
    })?;
    let registration = get_registration(&client, &who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    let judgement = substrate::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        judgement,
        Identity::from_str(&hash)?,
    );

    let signer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        // TODO: config the "//Alice" part?
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//FERDIE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &signer, conf).await {
        Ok(_) => return Ok("Judged with reasonable"),
        Err(_) => return Err(anyhow!("unable to submit judgement")),
    }
}

/// Filters all requested accounts to include only those that we can handle, and default
/// the judgement of other accounts to `Erroneous`, and the judgement for empty identity
/// objects to `Unknown`
pub async fn filter_accounts(
    info: &IdentityInfo,
    who: &AccountId32,
    reg_index: u32,
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

    // supported fields from cfg
    let supported = &network_cfg.fields;

    if accounts.is_empty() {
        provide_judgement(who, reg_index, Judgement::Unknown, &network_cfg.endpoint).await?;
        return Ok(HashMap::new());
    }

    for account in &accounts {
        let account_type = account.account_type();
        if !supported
            .iter()
            .any(|s| AccountType::from_str(s).ok() == Some(account_type))
        {
            provide_judgement(who, reg_index, Judgement::Erroneous, &network_cfg.endpoint).await?;
            return Ok(HashMap::new());
        }
    }

    Ok(Account::into_hashmap(accounts, false))
}

/// This will provide a [Reasonable] judgement for the account id `who` from the registrar with
/// index `regi_index`
// TODO: Takea RegistrarConfig instead?
pub async fn register_identity<'a>(
    who: &AccountId32,
    reg_index: u32,
    network: &str,
) -> anyhow::Result<&'a str> {
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

    let registration = get_registration(&client, who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    let judgement = substrate::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        Judgement::Reasonable,
        Identity::from_str(&hash)?,
    );

    // TODO: use from keyfile + add IdentityJudgement proxy
    let signer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//ALICE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &signer, conf).await {
        Ok(_) => Ok("Judged with reasonable"),
        Err(e) => Err(anyhow!("unable to submit judgement\nError: {:?}", e)),
    }
}
