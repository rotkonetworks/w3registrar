#![allow(dead_code)]

mod substrate;
mod api;

use anyhow::anyhow;
use anyhow::Result;
use subxt::utils::H256;

use std::collections::HashMap;

pub use subxt::utils::AccountId32 as AccountId;

pub type RegistrarIndex = u32;

pub type MaxFee = f64;

//------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Client {
    inner: api::Client,
}

impl Client {
    pub async fn from_url(url: &str) -> Result<Self> {
        Ok(Self::new(api::Client::from_url(url).await?))
    }

    fn new(inner: api::Client) -> Self {
        Self { inner }
    }

    pub async fn exec(&self, _cmd: &Command) -> Result<()> {
        todo!()
    }

    // TODO: Return a stream.
    pub async fn fetch_events(&self) -> Result<Vec<Event>> {
        // Get block 96
        // TODO: Figure out how to properly construct block hashes of the right type.

        let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
        let block = self.inner.blocks().at(hash).await?;

        let mut events = vec![];
        for event in block.events().await?.iter() {
            if let Ok(event) = event?.as_root_event::<api::Event>() {
                if let Some(event) = decode_api_event(event) {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    pub async fn fetch_contact(&self, id: &AccountId) -> Result<Contact> {
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
                Ok(Contact::new(id.clone(), decode_identity_info(reg.info)))
            },
            None => Err(anyhow!("Identity not found")),
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Batch(Vec<Self>),
    SetIdentity(AccountId, FieldMap),
    RequestJudgement(RegistrarIndex, MaxFee),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    JudgementRequested(AccountId, RegistrarIndex),
}

fn decode_api_event(event: api::Event) -> Option<Event> {
    match event {
        api::Event::Identity(e) => decode_api_identity_event(e),
        _ => None,
    }
}

fn decode_api_identity_event(event: api::IdentityEvent) -> Option<Event> {
    use api::IdentityEvent::*;
    match event {
        JudgementRequested { who, registrar_index } => {
            Some(Event::JudgementRequested(who, registrar_index))
        },
        // JudgementUnrequested { .. } => {}
        // JudgementGiven { .. } => {}
        // IdentitySet { .. } => {}
        // IdentityCleared { .. } => {}
        // IdentityKilled { .. } => {}
        _ => None,
    }
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug)]
pub struct Contact {
    pub id: AccountId,
    pub fields: FieldMap,
}

impl Contact {
    pub fn new(id: AccountId, fields: FieldMap) -> Self {
        Self { id, fields }
    }
}

//------------------------------------------------------------------------------

pub type FieldMap = HashMap<FieldKey, String>;

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