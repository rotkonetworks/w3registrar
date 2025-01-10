#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./identity.scale")]
pub mod api {}

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

use super::api::{identity_data_tostring, Account, VerifStatus};
use api::identity::calls::types::provide_judgement::Identity;
use api::runtime_types::pallet_identity::types::Judgement;
use api::runtime_types::pallet_identity::types::Registration;
use api::runtime_types::people_rococo_runtime::people::IdentityInfo;

pub use api::*;

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

    let judgement = api::tx().identity().provide_judgement(
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

// TODO: change the fn signature to include the accounts that we can handle
/// Filters all requested accounts to inlcude only those that we can handle, and default
/// the judgement of other accounts to `Erroneous`, and the judgement for empty identity
/// objects to `Unkown`
///
/// # Note
/// For now, we only handle registration requests from `Matrix`, `Twitter` and `Discord`
pub async fn filter_accounts(
    info: &IdentityInfo,
    who: &AccountId32,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<HashMap<Account, VerifStatus>> {
    let accounts = Account::into_accounts(&info);

    // if no accounts to verify, mark as Unknown
    if accounts.is_empty() {
        provide_judgement(who, reg_index, Judgement::Unknown, endpoint).await?;
        return Ok(HashMap::new());
    }
    // check if there are any accounts we don't handle
    // todo: make configurable via configs
    for account in &accounts {
        match account {
            Account::Matrix(_) |
                Account::Twitter(_) |
                Account::Discord(_) => continue,
            _ => {
                provide_judgement(who, reg_index, Judgement::Erroneous, endpoint).await?;
                return Ok(HashMap::new());
            }
        }
    }
    Ok(Account::into_hashmap(accounts, VerifStatus::Pending))
}

/// This will provide a [Reasonable] judgement for the account id `who` from the registrar with
/// index `regi_index`
pub async fn register_identity<'a>(
    who: &AccountId32,
    reg_index: u32,
    endpoint: &str,
) -> anyhow::Result<&'a str> {
    let client = Client::from_url(endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} network because of {}",
            endpoint,
            e.to_string(),
        )
    })?;
    let registration = get_registration(&client, who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    let judgement = api::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        Judgement::Reasonable,
        Identity::from_str(&hash)?,
    );

    let signer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//ALICE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &signer, conf).await {
        Ok(_) => return Ok("Judged with reasonable"),
        Err(e) => return Err(anyhow!("unable to submit judgement\nError: {:?}", e)),
    }
}
