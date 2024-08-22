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
    let client = api::Client::from_url(config.endpoint).await?;

    let mut sub = client.blocks().subscribe_finalized().await?;

    while let Some(block) = sub.next().await {
        let block = block?;
        let block = decode_block(block, config.registrar_index).await?;
        println!("{:#?}\n", block);
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
    fn new(inner: api::Client, registrar_index: RegistrarIndex) -> Self {
        Self { inner, registrar_index }
    }

    pub async fn from_config(config: ClientConfig) -> Result<Self> {
        let inner = api::Client::from_url(config.endpoint).await?;
        Ok(Self::new(inner, config.registrar_index))
    }

    pub async fn fetch_block(&self, hash: &str) -> Result<Block> {
        let hash = hash.parse::<H256>()?;
        let block = self.inner.blocks().at(hash).await?;
        decode_block(block, self.registrar_index).await
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

async fn decode_block(block: api::Block, ri: RegistrarIndex) -> Result<Block> {
    let mut events = vec![];
    for event in block.events().await?.iter() {
        if let Ok(event) = event?.as_root_event::<api::Event>() {
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

fn decode_api_event(event: api::Event, ri: RegistrarIndex) -> Option<Event> {
    match event {
        api::Event::Identity(e) => decode_api_identity_event(e, ri),
        _ => None,
    }
}

fn decode_api_identity_event(event: api::IdentityEvent, ri: RegistrarIndex) -> Option<Event> {
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
