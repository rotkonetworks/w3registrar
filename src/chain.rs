#![allow(dead_code)]

use crate::node;
pub use crate::node::{AccountId, BlockHash, BlockNumber, Client, RegistrarIndex};

use anyhow::Result;
use tokio::sync::mpsc;

// TODO: Name?
pub struct Blocks {
    client: Client,
}

impl Blocks {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn fetch(&self, hash: &str, tx: &mpsc::Sender<Block>) -> Result<()> {
        let hash = hash.parse::<BlockHash>()?;

        let block = self.client.blocks().at(hash).await?;
        let block = decode_block(&block).await?;
        tx.send(block).await?;

        Ok(())
    }

    pub async fn fetch_incoming(&self, tx: &mpsc::Sender<Block>) -> Result<()> {
        let mut sub = self.client.blocks().subscribe_finalized().await?;

        while let Some(block) = sub.next().await {
            let block = decode_block(&block?).await?;
            tx.send(block).await?;
        }

        Ok(())
    }
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