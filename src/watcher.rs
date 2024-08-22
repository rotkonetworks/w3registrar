#![allow(dead_code)]

use crate::node;
use crate::node::{BlockHash, Client, RegistrarIndex};
use crate::db::{Block, Event};

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: Config) -> Result<()> {
    let client = Client::from_url(cfg.endpoint).await?;

    let mut sub = client.blocks().subscribe_finalized().await?;

    while let Some(block) = sub.next().await {
        let block = block?;
        let block = decode_block(block, cfg.registrar_index).await?;
        println!("{:#?}\n", block);
    }

    Ok(())
}

pub async fn fetch_block(cfg: Config, hash: &str) -> Result<Block> {
    let client = Client::from_url(cfg.endpoint).await?;

    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;

    decode_block(block, cfg.registrar_index).await
}

//------------------------------------------------------------------------------

async fn decode_block(block: node::Block, ri: RegistrarIndex) -> Result<Block> {
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
        hash: block.hash().to_string(),
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
