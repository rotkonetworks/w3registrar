#![allow(dead_code)]

use crate::node;

pub use crate::node::{AccountId, BlockHash, Client, RegistrarIndex};

use crate::node::substrate::api::runtime_types::pallet_identity::types::Data;
use crate::node::substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use crate::node::substrate::api::storage;

use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub struct EventSource {
    client: Client,
    registrar_index: RegistrarIndex,
}

impl EventSource {
    pub fn new(client: Client, registrar_index: RegistrarIndex) -> Self {
        Self { client, registrar_index }
    }

    pub async fn fetch_from_block(&self, hash: &str, tx: &mpsc::Sender<Event>) -> Result<()> {
        let hash = hash.parse::<BlockHash>()?;
        let block = self.client.blocks().at(hash).await?;
        self.process_block(block, &tx).await
    }

    pub async fn fetch_incoming(&self, tx: &mpsc::Sender<Event>) -> Result<()> {
        let mut sub = self.client.blocks().subscribe_finalized().await?;
        while let Some(block) = sub.next().await {
            self.process_block(block?, &tx).await?;
        }
        Ok(())
    }

    // PRIVATE

    async fn process_block(&self, block: node::Block, tx: &mpsc::Sender<Event>) -> Result<()> {
        for event in block.events().await?.iter() {
            if let Ok(event) = event?.as_root_event::<node::Event>() {
                if let Some(event) = self.decode_api_event(event) {
                    tx.send(event).await?;
                }
            }
        }
        Ok(())
    }

    fn decode_api_event(&self, event: node::Event) -> Option<Event> {
        match event {
            node::Event::Identity(e) => self.decode_api_identity_event(e),
            _ => None,
        }
    }

    fn decode_api_identity_event(&self, event: node::IdentityEvent) -> Option<Event> {
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
}

pub async fn fetch_identity(client: &Client, id: &AccountId) -> Result<Option<Identity>> {
    let query = storage()
        .identity()
        .identity_of(id);

    let identity = client
        .storage()
        .at_latest()
        .await?
        .fetch(&query)
        .await?;

    Ok(identity.map(|(reg, _)| {
        decode_identity_info(reg.info)
    }))
}

//------------------------------------------------------------------------------

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

//------------------------------------------------------------------------------

pub type Identity = HashMap<IdentityKey, String>;

// TODO: Add PgpFingerprint
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IdentityKey {
    Display,
    Legal,
    Web,
    Matrix,
    Email,
    Image,
    Twitter,
    Github,
    Discord,
}

fn decode_identity_info(info: IdentityInfo) -> Identity {
    use IdentityKey::*;
    let mut fields = HashMap::new();
    decode_identity_field_into(Display, info.display, &mut fields);
    decode_identity_field_into(Legal, info.legal, &mut fields);
    decode_identity_field_into(Web, info.web, &mut fields);
    decode_identity_field_into(Matrix, info.matrix, &mut fields);
    decode_identity_field_into(Email, info.email, &mut fields);
    decode_identity_field_into(Image, info.image, &mut fields);
    decode_identity_field_into(Twitter, info.twitter, &mut fields);
    decode_identity_field_into(Github, info.github, &mut fields);
    decode_identity_field_into(Discord, info.discord, &mut fields);
    fields
}

fn decode_identity_field_into(key: IdentityKey, value: Data, fields: &mut Identity) {
    if let Some(s) = decode_string_data(value) {
        fields.insert(key, s);
    }
}

fn decode_string_data(data: Data) -> Option<String> {
    use Data::*;
    match data {
        Raw0(b) => Some(string_from_bytes(&b)),
        Raw1(b) => Some(string_from_bytes(&b)),
        Raw2(b) => Some(string_from_bytes(&b)),
        Raw3(b) => Some(string_from_bytes(&b)),
        Raw4(b) => Some(string_from_bytes(&b)),
        Raw5(b) => Some(string_from_bytes(&b)),
        Raw6(b) => Some(string_from_bytes(&b)),
        Raw7(b) => Some(string_from_bytes(&b)),
        Raw8(b) => Some(string_from_bytes(&b)),
        Raw9(b) => Some(string_from_bytes(&b)),
        Raw10(b) => Some(string_from_bytes(&b)),
        Raw11(b) => Some(string_from_bytes(&b)),
        Raw12(b) => Some(string_from_bytes(&b)),
        Raw13(b) => Some(string_from_bytes(&b)),
        Raw14(b) => Some(string_from_bytes(&b)),
        Raw15(b) => Some(string_from_bytes(&b)),
        Raw16(b) => Some(string_from_bytes(&b)),
        Raw17(b) => Some(string_from_bytes(&b)),
        Raw18(b) => Some(string_from_bytes(&b)),
        Raw19(b) => Some(string_from_bytes(&b)),
        Raw20(b) => Some(string_from_bytes(&b)),
        Raw21(b) => Some(string_from_bytes(&b)),
        Raw22(b) => Some(string_from_bytes(&b)),
        Raw23(b) => Some(string_from_bytes(&b)),
        Raw24(b) => Some(string_from_bytes(&b)),
        Raw25(b) => Some(string_from_bytes(&b)),
        Raw26(b) => Some(string_from_bytes(&b)),
        Raw27(b) => Some(string_from_bytes(&b)),
        Raw28(b) => Some(string_from_bytes(&b)),
        Raw29(b) => Some(string_from_bytes(&b)),
        Raw30(b) => Some(string_from_bytes(&b)),
        Raw31(b) => Some(string_from_bytes(&b)),
        Raw32(b) => Some(string_from_bytes(&b)),
        _ => Option::None,
    }
}

fn string_from_bytes(bytes: &[u8]) -> String {
    std::str::from_utf8(&bytes).unwrap_or("").to_string()
}