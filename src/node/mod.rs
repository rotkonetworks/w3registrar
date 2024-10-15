#![allow(dead_code)]

mod substrate;
mod api;

use anyhow::{Result, anyhow};
use async_stream::try_stream;
use subxt::{PolkadotConfig, SubstrateConfig};
use tokio_stream::Stream;

pub use api::*;

pub type Client = subxt::OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;

pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;

pub use subxt::utils::AccountId32 as AccountId;
use subxt::utils::MultiAddress;

pub type RegistrarIndex = u32;

pub type IdentityHash = subxt::ext::subxt_core::utils::H256;

use subxt::tx::signer::PairSigner;
use subxt_signer::sr25519::Keypair;

use sp_core::Pair;
use sp_core::sr25519::Pair as Sr25519Pair;

#[derive(Debug)]
pub struct JudgementEnvelope {
    pub registrar_index: RegistrarIndex,
    pub target: AccountId,
    pub judgement: Judgement,
    pub identity_hash: IdentityHash,
}

pub async fn provide_judgement(
    client: &Client,
    seed_phrase: String,
    registrar_account: AccountId,
    env: JudgementEnvelope
) -> Result<()> {
    let keypair = Sr25519Pair::from_phrase(&seed_phrase, None)
        .map_err(|e| anyhow!("Failed to create key pair: {:?}", e))?;

    let pair_signer: PairSigner<SubstrateConfig, Keypair> = PairSigner::new(keypair);

    let inner_call = tx().identity().provide_judgement(
        env.registrar_index,
        MultiAddress::Id(env.target.clone()),
        env.judgement,
        env.identity_hash,
    );

    let proxy_call = tx().proxy().proxy(
        MultiAddress::Id(registrar_account.clone()),
        None, // TODO: ProxyType::IdentityJudgement
        inner_call,
    );

    let tx_progress = client.tx()
        .sign_and_submit_then_watch_default(&proxy_call, &pair_signer)
        .await?;

    tx_progress.wait_for_finalized_success().await?;

    Ok(())
}


pub async fn subscribe_to_events(
    client: &Client
) -> Result<impl Stream<Item = Result<Event>>> {
    let mut block_stream = client.blocks().subscribe_finalized().await?;

    Ok(try_stream! {
        while let Some(item) = block_stream.next().await {
            let block = item?;
            for event in events_from_block(block).await?.into_iter() {
                yield event;
            }
        }
    })
}

pub async fn events_from_block(block: Block) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for item in block.events().await?.iter() {
        let details = item?;
        if let Ok(event) = details.as_root_event::<Event>() {
            events.push(event);
        }
    }
    Ok(events)
}

pub async fn get_registration(
    client: &Client, who: &AccountId
) -> Result<Registration> {
    let storage = client.storage().at_latest().await?;
    let address = api::storage().identity().identity_of(who);
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}
