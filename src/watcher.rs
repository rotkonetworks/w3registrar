#![allow(dead_code)]

use crate::node;
use crate::node::{BlockHash, Client, RegistrarIndex};
use crate::repo::{Block, Database, Event};

use anyhow::Result;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: Config, db: &Database) -> Result<()> {
    let client = Client::from_url(cfg.endpoint).await?;

    let mut sub = client.blocks().subscribe_finalized().await?;

    let mut last_hash = db.get_last_block_hash().await?;

    while let Some(block) = sub.next().await {
        let block = block?;

        if let Some(end_hash) = last_hash {
            info!("Fetching backwards to block {:?}", end_hash);

            let start_hash = block.header().parent_hash;

            let client = client.clone();
            let db = db.clone();

            tokio::spawn(async move {
                process_blocks_in_range(
                    &client,
                    &db,
                    cfg.registrar_index,
                    start_hash,
                    end_hash
                ).await
            });

            last_hash = None;
        }

        let block = decode_block(&block, cfg.registrar_index).await?;
        warn!("Received {:#?}", block);

        db.save_block(block).await?;
    }

    Ok(())
}

pub async fn process_block(cfg: Config, hash: &str, db: &Database) -> Result<()> {
    let client = Client::from_url(cfg.endpoint).await?;

    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;

    let block = decode_block(&block, cfg.registrar_index).await?;
    info!("Fetched {:#?}", block);

    db.save_block(block).await
}

async fn process_blocks_in_range(
    client: &Client,
    db: &Database,
    ri: RegistrarIndex,
    start_hash: BlockHash,
    end_hash: BlockHash
) -> Result<()> {
    let client = client.blocks();

    let mut current_hash = start_hash;

    while current_hash != end_hash {
        let block = client.at(current_hash).await?;
        let parent_hash = block.header().parent_hash;

        let block = decode_block(&block, ri).await?;
        info!("Fetched {:#?}", block);

        db.save_block(block).await?;

        // if parent_hash == block.hash() {
        //     info!("Reached the genesis block");
        //     break;
        // }

        current_hash = parent_hash;
    }

    Ok(())
}

//------------------------------------------------------------------------------

async fn decode_block(block: &node::Block, ri: RegistrarIndex) -> Result<Block> {
    let mut events = vec![];
    for event in block.events().await?.iter() {
        if let Ok(event) = event?.as_root_event::<node::Event>() {
            if let Some(event) = decode_api_event(event, ri) {
                events.push(event);
            }
        }
    }

    Ok(Block {
        number: block.number().into(),
        hash: block.hash(),
        events,
    })
}

fn decode_api_event(event: node::Event, ri: RegistrarIndex) -> Option<Event> {
    match event {
        node::Event::Identity(e) => decode_api_identity_event(e, ri),
        _ => None,
    }
}

fn decode_api_identity_event(event: node::IdentityEvent, ri: RegistrarIndex) -> Option<Event> {
    use node::IdentityEvent::*;
    match event {
        IdentitySet { who } => {
            Some(Event::IdentitySet(who))
        }

        IdentityCleared { who, .. } => {
            Some(Event::IdentityCleared(who))
        }

        IdentityKilled { who, .. } => {
            Some(Event::IdentityKilled(who))
        }

        JudgementRequested { who, registrar_index }
        if registrar_index == ri => {
            Some(Event::JudgementRequested(who))
        }

        JudgementUnrequested { who, registrar_index }
        if registrar_index == ri => {
            Some(Event::JudgementUnrequested(who))
        }

        JudgementGiven { target, registrar_index }
        if registrar_index == ri => {
            Some(Event::JudgementGiven(target))
        }

        _ => None
    }
}