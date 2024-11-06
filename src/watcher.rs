#![allow(dead_code)]

use crate::node;

use serde::Deserialize;
use tokio_stream::StreamExt;

pub use node::RegistrarIndex;

use node::BlockHash;
use node::Client;
use node::Event;
use node::Identity;
use node::Judgement;
use node::JudgementEnvelope;

const JUDGEMENT_REQUESTED_BLOCK: &str =
    "0xcd1d14950d301b0cd2660532aec68e3d62b207e257cf7af5453b09ddd888caf7";

const SEED_PHRASE: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

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
    use node::Event::*;

    match event {
        JudgementRequested { who, registrar_index } if registrar_index == ri => {
            use sp_core::Encode;
            use sp_core::blake2_256;

            let reg = node::get_registration(&client, &who).await?;

            // TODO: Clean this up.
            let has_paid_fee = reg
                .judgements
                .0
                .iter()
                .any(|(_, j)| matches!(j, Judgement::FeePaid(_)));

            if has_paid_fee {
                println!("Judgement requested by {}", who);

                let encoded_info = reg.info.encode();
                let hash_bytes = blake2_256(&encoded_info);
                let identity_hash = Identity::from(&hash_bytes);
                println!("Identity hash {:?}", identity_hash);

                node::provide_judgement(&client, SEED_PHRASE, JudgementEnvelope {
                    registrar_index,
                    target: who,
                    judgement: Judgement::Erroneous,
                    identity_hash,
                }).await?;
            }
        }
        _ => {
            // info!("Ignoring {:?}", event);
        }
    }

    Ok(())
}
