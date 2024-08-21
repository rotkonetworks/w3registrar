#![allow(dead_code)]

mod substrate;
mod api;

use anyhow::anyhow;
use anyhow::Result;
use subxt::utils::H256;
use serde::Deserialize;

use std::collections::HashMap;

pub use subxt::utils::AccountId32 as AccountId;
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

    // TODO: Return a stream.
    pub async fn fetch_events(&self) -> Result<Vec<Event>> {
        // Get block 96
        let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
        let block = self.inner.blocks().at(hash).await?;

        let mut events = vec![];
        for event in block.events().await?.iter() {
            if let Ok(event) = event?.as_root_event::<api::Event>() {
                if let Some(event) = self.decode_api_event(event).await? {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }
}

// PRIVATE

impl Client {
    fn new(inner: api::Client, registrar_index: RegistrarIndex) -> Self {
        Self { inner, registrar_index }
    }

    async fn decode_api_event(&self, event: api::Event) -> Result<Option<Event>> {
        match event {
            api::Event::Identity(e) => {
                self.decode_api_identity_event(e).await
            },
            _ => Ok(None),
        }
    }

    async fn decode_api_identity_event(&self, event: api::IdentityEvent) -> Result<Option<Event>> {
        use api::IdentityEvent::*;
         match event {
            JudgementRequested { who, registrar_index } => {
                if registrar_index == self.registrar_index {
                    let fields = self.fetch_contact_details(&who).await?;
                    Ok(Some(Event::JudgementRequested(who, fields)))
                } else {
                    Err(anyhow!("Invalid registrar index {}", registrar_index))
                }
            },
            // JudgementUnrequested { .. } => {}
            // JudgementGiven { .. } => {}
            // IdentitySet { .. } => {}
            // IdentityCleared { .. } => {}
            // IdentityKilled { .. } => {}
            _ => Ok(None),
        }
    }

    async fn fetch_contact_details(&self, id: &AccountId) -> Result<FieldMap> {
        let query = api::storage()
            .identity()
            .identity_of(id);

        let identity = self.inner
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?;

        match identity {
            Some((reg, _)) => {
                Ok(decode_identity_info(reg.info))
            },
            None => Err(anyhow!("Identity not found")),
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    RequestJudgement(AccountId, MaxFee, FieldMap),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    JudgementRequested(AccountId, FieldMap),
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