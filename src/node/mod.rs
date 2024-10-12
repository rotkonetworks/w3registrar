mod api;

pub use api::*;

use anyhow::anyhow;
use async_stream::try_stream;
use tokio_stream::Stream;
use tracing::info;

pub type Client = subxt::OnlineClient<subxt::SubstrateConfig>;

pub async fn subscribe_to_identity_events(
    client: &Client,
) -> anyhow::Result<impl Stream<Item = anyhow::Result<IdentityEvent>>> {
    let mut block_stream = client.blocks().subscribe_finalized().await?;

    Ok(try_stream! {
        while let Some(block_res) = block_stream.next().await {
            let block = block_res?;
            for event_res in block.events().await?.iter() {
                let event_details = event_res?;
                if let Ok(event) = event_details.as_root_event::<Event>() {
                    info!("Received {:?}", event);
                    match event {
                        Event::Identity(e) => yield e,
                    };
                }
            }
        }
    })
}

pub async fn get_registration(
    client: &Client, who: &AccountId32
) -> anyhow::Result<Registration> {
    let storage = client.storage().at_latest().await?;
    let address = identity_of(who);
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}
