#![allow(dead_code)]

mod substrate;
mod api;

pub use api::AccountId;

use subxt::utils::H256;
use anyhow::Result;
use serde::Deserialize;

use std::collections::HashMap;

pub type RegistrarIndex = u32;
pub type MaxFee = f64;

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

    pub async fn exec(&self, _cmd: Command) -> Result<()> {
        todo!()
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

    pub async fn fetch_contact_details(&self, id: &AccountId) -> Result<Option<FieldMap>> {
        let query = api::storage()
            .identity()
            .identity_of(id);

        let identity = self.inner
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?;

        Ok(identity.map(|(reg, _)| {
            decode_identity_info(reg.info)
        }))
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
pub enum Command {
    Batch(Vec<Self>),
    RequestJudgement(AccountId, MaxFee),
    ProvideJudgement(AccountId, Judgement),
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Judgement {
    Good,
    Bad,
}

//------------------------------------------------------------------------------

pub type FieldMap = HashMap<FieldKey, String>;

// TODO: Name?
pub type Field = (FieldKey, String);

// TODO: Add PgpFingerprint
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FieldKey {
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

fn decode_identity_info(info: api::IdentityInfo) -> FieldMap {
    use FieldKey::*;
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

fn decode_identity_field_into(key: FieldKey, value: api::Data, fields: &mut FieldMap) {
    if let Some(s) = decode_string_data(value) {
        fields.insert(key, s);
    }
}

fn decode_string_data(data: api::Data) -> Option<String> {
    use api::Data::*;
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