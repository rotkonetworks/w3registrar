#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./identity.scale")]
pub mod api {}

use anyhow::{anyhow, Result};
use sp_core::blake2_256;
use sp_core::Encode;
use std::str::FromStr;
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::SubstrateConfig;
use tracing::info;

use api::runtime_types::pallet_identity::types::Registration;
use api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use subxt::utils::AccountId32;

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

pub async fn register_identity<'a>(who: AccountId32, reg_index: u32) -> anyhow::Result<&'a str> {
    let client = Client::from_url("wss://dev.rotko.net/people-rococo")
        .await
        .map_err(|e| {
            anyhow!(
                "unable to connect to people-rococo network because of {}",
                e.to_string()
            )
        })?;
    let registration = get_registration(&client, &who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));
    let judgement = api::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        runtime_types::pallet_identity::types::Judgement::Reasonable,
        api::identity::calls::types::provide_judgement::Identity::from_str(&hash)?,
    );

    let singer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//ALICE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &singer, conf).await {
        Ok(_) => return Ok("Judged with "),
        Err(_) => return Err(anyhow!("unable to submit judgement")),
    }
}
