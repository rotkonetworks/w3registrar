mod api;

use std::pin::Pin;

pub use api::runtime_types::pallet_identity::pallet::Event as IdentityEvent;
pub use api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use futures::StreamExt;
pub use subxt::utils::AccountId32 as AccountId;

use anyhow::{anyhow, Result};
use async_stream::try_stream;
use subxt::{OnlineClient, SubstrateConfig};
use tokio_stream::Stream;

use crate::config::WatcherConfig;

pub type Client = subxt::OnlineClient<subxt::SubstrateConfig>;

pub type Registration =
    api::runtime_types::pallet_identity::types::Registration<u128, IdentityInfo>;

pub type Judgement = api::runtime_types::pallet_identity::types::Judgement<u128>;

pub type RegistrarIndex = u32;

pub async fn subscribe_to_identity_events(
    client: &Client,
) -> Result<impl Stream<Item = Result<IdentityEvent>>> {
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

pub async fn event_manager<'a>(
    mut event_stream: Pin<&'a mut impl futures::Stream<Item = Result<IdentityEvent>>>,
    cfg: WatcherConfig,
    client: OnlineClient<SubstrateConfig>,
) -> Result<()> {
    while let Some(event_res) = event_stream.next().await {
        use api::runtime_types::pallet_identity::pallet::Event::*;

        let event = event_res?;
        match event {
            IdentitySet { who } | IdentityCleared { who, .. } | IdentityKilled { who, .. } => {
                println!("Identity changed for {}", who);
            }
            JudgementRequested {
                who,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    let reg = get_registration(&client, &who).await?;
                    // TODO: Clean this up.
                    let has_paid_fee = reg
                        .judgements
                        .0
                        .iter()
                        .any(|(_, j)| matches!(j, Judgement::FeePaid(_)));
                    if has_paid_fee {
                        println!("Judgement requested by {}: {:#?}", who, reg.info);
                    }
                }
            }
            JudgementUnrequested {
                who,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    println!("Judgement unrequested by {}", who);
                }
            }
            JudgementGiven {
                target,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    let reg = get_registration(&client, &target).await?;
                    // TODO: Clean this up.
                    if let Some(judgement) = reg.judgements.0.last().map(|(j, _)| *j) {
                        println!("Judgement given to {}: {:?}", target, judgement);
                    }
                }
            }
            _ => {
                println!("{:?}", event);
            }
        }
    }

    Ok(())
}
