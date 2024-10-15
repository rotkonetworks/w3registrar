#![allow(dead_code)]

mod substrate;
mod api;

use anyhow::{Result, anyhow};
use async_stream::try_stream;
use subxt::SubstrateConfig;
use tokio_stream::Stream;

pub use api::*;

pub type Client = subxt::OnlineClient<SubstrateConfig>;

pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;

pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;

pub use subxt::utils::AccountId32 as AccountId;

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
