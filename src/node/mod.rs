mod substrate;
mod api;

pub use api::{AccountId, Client, IdentityEvent, Registration, Judgement};

use anyhow::{anyhow, Result};
use async_stream::try_stream;
use tokio_stream::Stream;

pub type RegistrarIndex = u32;

pub async fn subscribe_to_identity_events(
    client: &Client
) -> Result<impl Stream<Item=Result<IdentityEvent>>> {
    let mut block_stream = client.blocks().subscribe_finalized().await?;

    Ok(try_stream! {
        while let Some(block_res) = block_stream.next().await {
            let block = block_res?;
            for event_res in block.events().await?.iter() {
                let event_details = event_res?;
                if let Ok(event) = event_details.as_root_event::<api::Event>() {
                    match event {
                        api::Event::Identity(e) => {
                            yield e;
                        }
                        _ => {}
                    };
                }
            }
        }
    })
}

pub async fn get_registration(client: &Client, who: &AccountId) -> Result<Registration> {
    let storage = client.storage().at_latest().await?;
    let address = api::storage().identity().identity_of(who);
    match storage.fetch(&address).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}
