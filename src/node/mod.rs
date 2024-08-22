#![allow(dead_code)]

mod substrate;
mod api;

pub use api::AccountId;

use subxt::utils::H256;
use anyhow::Result;
use serde::Deserialize;

pub type RegistrarIndex = u32;
pub type MaxFee = f64;

pub async fn run_watcher(config: ClientConfig) -> Result<()> {
    // Create a client to use:
    let api = api::Client::from_url(config.endpoint).await?;

    // Subscribe to all finalized blocks:
    let mut blocks_sub = api.blocks().subscribe_finalized().await?;

    // For each block, print a bunch of information about it:
    while let Some(block) = blocks_sub.next().await {
        let block = block?;

        let number = block.header().number;
        let hash = block.hash();

        println!("Block #{}, {}", number, hash);
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

#[derive(Debug, Clone)]
pub struct Client {
    inner: api::Client,
    registrar_index: RegistrarIndex,
}

impl Client {
    pub async fn from_config(config: ClientConfig) -> Result<Self> {
        let inner = api::Client::from_url(config.endpoint).await?;
        Ok(Self::new(inner, config.registrar_index))
    }

    pub async fn fetch_block(&self, hash: &str) -> Result<Block> {
        let hash = hash.parse::<H256>()?;
        let block = self.inner.blocks().at(hash).await?;

        let mut events = vec![];
        for event in block.events().await?.iter() {
            if let Ok(event) = event?.as_root_event::<api::Event>() {
                if let Some(event) = self.decode_api_event(event) {
                    events.push(event);
                }
            }
        }

        Ok(Block {
            number: block.number().into(),
            hash: hash.to_string(),
            events,
        })
    }
}

// PRIVATE

impl Client {
    fn new(inner: api::Client, registrar_index: RegistrarIndex) -> Self {
        Self { inner, registrar_index }
    }

    fn decode_api_event(&self, event: api::Event) -> Option<Event> {
        match event {
            api::Event::Identity(e) => self.decode_api_identity_event(e),
            _ => None,
        }
    }

    fn decode_api_identity_event(&self, event: api::IdentityEvent) -> Option<Event> {
        use api::IdentityEvent::*;
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
            if registrar_index == self.registrar_index => {
                Some(Event::JudgementRequested(who))
            }

            JudgementUnrequested { who, registrar_index }
            if registrar_index == self.registrar_index => {
                Some(Event::JudgementUnrequested(who))
            }

            JudgementGiven { target, registrar_index }
            if registrar_index == self.registrar_index => {
                Some(Event::JudgementGiven(target))
            }

            _ => None
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Block {
    pub number: u64,
    pub hash: String,
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

impl Event {
    pub fn target(&self) -> &AccountId {
        match self {
            | Event::IdentitySet(id)
            | Event::IdentityCleared(id)
            | Event::IdentityKilled(id)
            | Event::JudgementRequested(id)
            | Event::JudgementUnrequested(id)
            | Event::JudgementGiven(id) => {
                id
            }
        }
    }
}
