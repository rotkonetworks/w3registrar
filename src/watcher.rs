#![allow(dead_code)]

use crate::node;

use serde::Deserialize;
use tokio_stream::StreamExt;

use node::{Client, Event, BlockHash};

pub type RegistrarIndex = u32;

const JUDGEMENT_REQUESTED_BLOCK: &str =
    "0xece2b31d1df2d9ff118bb1ced539e395fbabf0987120ff2eed6610d0b7bd6b39";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let client = Client::from_url(cfg.endpoint.as_str()).await?;
    let ri = cfg.registrar_index;

    process_block(&client, ri, JUDGEMENT_REQUESTED_BLOCK).await?;
    // watch_node(&client, ri).await?;

    Ok(())
}

pub async fn process_block(client: &Client, ri: RegistrarIndex, hash: &str) -> anyhow::Result<()> {
    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;
    for event in node::events_from_block(block).await?.into_iter() {
        handle_event(&client, ri, event).await?;
    }
    Ok(())
}

async fn watch_node(client: &Client, ri: RegistrarIndex) -> anyhow::Result<()> {
    let event_stream = node::subscribe_to_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(item) = event_stream.next().await {
        let event = item?;
        handle_event(&client, ri, event).await?;
    }

    Ok(())
}

async fn handle_event(client: &Client, ri: RegistrarIndex, event: Event) -> anyhow::Result<()> {
    use node::IdentityEvent::*;

    match event {
        Event::Identity(JudgementRequested { who, registrar_index })
        if registrar_index == ri => {
            use sp_core::Encode;
            use sp_core::blake2_256;

            let reg = node::get_registration(&client, &who).await?;

            // TODO: Clean this up.
            let has_paid_fee = reg
                .judgements
                .0
                .iter()
                .any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));

            if has_paid_fee {
                let encoded_info = reg.info.encode();
                let hash = blake2_256(&encoded_info);
                let hash_str = hex::encode(&hash);

                println!("Judgement requested by {}", who);
                println!("Identity hash 0x{}", hash_str);
            }
        }
        _ => {
            // info!("Ignoring {:?}", event);
        }
    }

    Ok(())
}
