#![allow(dead_code)]

mod api;

use anyhow::{anyhow, Result};
use async_stream::try_stream;
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::SubstrateConfig;
use tokio_stream::Stream;

pub use api::*;

pub type Client = subxt::OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;

pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;

type PairSigner = subxt::tx::PairSigner<SubstrateConfig, Sr25519Pair>;

#[derive(Debug)]
pub struct JudgementEnvelope {
    pub registrar_index: RegistrarIndex,
    pub target: AccountId,
    pub judgement: Judgement,
    pub identity_hash: Identity,
}

pub async fn provide_judgement(
    client: &Client,
    seed_phrase: &str,
    env: JudgementEnvelope
) -> Result<()> {
    let pair = Sr25519Pair::from_phrase(&seed_phrase, None)?;
    let signer = PairSigner::new(pair.0);

    let call = api::provide_judgement(
        env.registrar_index,
        Target::Id(env.target.clone()),
        env.judgement,
        env.identity_hash,
    );

    client.tx()
        .sign_and_submit_then_watch_default(&call, &signer)
        .await?
        .wait_for_finalized_success()
        .await?;

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
    let address = api::identity_of(who);
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}
