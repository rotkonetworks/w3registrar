#![allow(dead_code)]

use crate::node;
use crate::node::{AccountId, BlockHash, BlockNumber, Client, RegistrarIndex};

use anyhow::Result;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: &Config) -> Result<()> {
    let client = Client::from_url(&cfg.endpoint).await?;

    let mut sub = client.blocks().subscribe_finalized().await?;

    while let Some(block) = sub.next().await {
        let block = block?;

        let block = decode_block(&block).await?;
        warn!("Received {:#?}", block);
    }

    Ok(())
}

pub async fn process_block(cfg: &Config, hash: &str) -> Result<()> {
    let client = Client::from_url(&cfg.endpoint).await?;

    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;

    let block = decode_block(&block).await?;
    info!("Fetched {:#?}", block);

    Ok(())
}

async fn process_blocks_in_range(
    client: &Client,
    start_hash: BlockHash,
    end_hash: BlockHash
) -> Result<()> {
    let client = client.blocks();

    let mut current_hash = start_hash;

    while current_hash != end_hash {
        let block = client.at(current_hash).await?;
        let parent_hash = block.header().parent_hash;

        let block = decode_block(&block).await?;
        info!("Fetched {:#?}", block);

        // if parent_hash == block.hash() {
        //     info!("Reached the genesis block");
        //     break;
        // }

        current_hash = parent_hash;
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Block {
    pub number: BlockNumber,
    pub hash: BlockHash,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    IdentitySet(AccountId),
    IdentityCleared(AccountId),
    IdentityKilled(AccountId),
    JudgementRequested(AccountId, RegistrarIndex),
    JudgementUnrequested(AccountId, RegistrarIndex),
    JudgementGiven(AccountId, RegistrarIndex),
}

impl Event {
    pub fn target(&self) -> &AccountId {
        use Event::*;
        match self {
            | IdentitySet(id)
            | IdentityCleared(id)
            | IdentityKilled(id)
            | JudgementRequested(id, _)
            | JudgementUnrequested(id, _)
            | JudgementGiven(id, _) => {
                id
            }
        }
    }
}

async fn decode_block(block: &node::Block) -> Result<Block> {
    let mut events = vec![];
    for event in block.events().await?.iter() {
        if let Ok(event) = event?.as_root_event::<node::Event>() {
            if let Some(event) = decode_api_event(event) {
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

fn decode_api_event(event: node::Event) -> Option<Event> {
    match event {
        node::Event::Identity(e) => decode_api_identity_event(e),
        _ => None,
    }
}

fn decode_api_identity_event(event: node::IdentityEvent) -> Option<Event> {
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

        JudgementRequested { who, registrar_index } => {
            Some(Event::JudgementRequested(who, registrar_index))
        }

        JudgementUnrequested { who, registrar_index } => {
            Some(Event::JudgementUnrequested(who, registrar_index))
        }

        JudgementGiven { target, registrar_index } => {
            Some(Event::JudgementGiven(target, registrar_index))
        }

        _ => None
    }
}