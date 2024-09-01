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

        let block = decode_block(&block, cfg.registrar_index).await?;
        warn!("Received {:#?}", block);
    }

    Ok(())
}

pub async fn process_block(cfg: &Config, hash: &str) -> Result<()> {
    let client = Client::from_url(&cfg.endpoint).await?;

    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;

    let block = decode_block(&block, cfg.registrar_index).await?;
    info!("Fetched {:#?}", block);

    Ok(())
}

async fn process_blocks_in_range(
    client: &Client,
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
    JudgementRequested(AccountId),
    JudgementUnrequested(AccountId),
    JudgementGiven(AccountId),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EventKind {
    IdentitySet,
    IdentityCleared,
    IdentityKilled,
    JudgementRequested,
    JudgementUnrequested,
    JudgementGiven,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        use Event::*;
        match self {
            IdentitySet(_) => EventKind::IdentitySet,
            IdentityCleared(_) => EventKind::IdentityCleared,
            IdentityKilled(_) => EventKind::IdentityKilled,
            JudgementRequested(_) => EventKind::JudgementRequested,
            JudgementUnrequested(_) => EventKind::JudgementUnrequested,
            JudgementGiven(_) => EventKind::JudgementGiven,
        }
    }

    pub fn target(&self) -> &AccountId {
        use Event::*;
        match self {
            | IdentitySet(id)
            | IdentityCleared(id)
            | IdentityKilled(id)
            | JudgementRequested(id)
            | JudgementUnrequested(id)
            | JudgementGiven(id) => {
                id
            }
        }
    }
}

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