mod substrate;
mod api;

use subxt::utils::H256;
use anyhow::anyhow;
use anyhow::Result;
use serde::Deserialize;

use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Client {
    inner: api::Client,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub endpoint: String,
    pub registrar_index: u32,
    pub keystore_path: String,
}

impl Client {
    pub async fn with_config(config: ClientConfig) -> Result<Self> {
        Ok(Self::new(api::Client::from_url(config.endpoint).await?))
    }

    fn new(inner: api::Client) -> Self {
        Self { inner }
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
                if let Some(event) = self.process_event(event).await? {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    async fn process_event(&self, event: api::Event) -> Result<Option<Event>> {
        match event {
            api::Event::Identity(e) => self.process_identity_event(e).await,
            _ => Ok(None),
        }
    }

    async fn process_identity_event(&self, event: api::IdentityEvent) -> Result<Option<Event>> {
        use api::IdentityEvent::*;
        match event {
            JudgementRequested { who, .. } => {
                let (reg, _) = self.fetch_identity_of(&who).await?;
                let info = reg.info;
                let ids = decode_identity_info(info);
                Ok(Some(Event::JudgementRequested(who, ids)))
            },
            // JudgementUnrequested { .. } => {}
            // JudgementGiven { .. } => {}
            // IdentitySet { .. } => {}
            // IdentityCleared { .. } => {}
            // IdentityKilled { .. } => {}
            _ => Ok(None),
        }
    }

    async fn fetch_identity_of(&self, id: &AccountId) -> Result<api::IdentityOf> {
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
            Some(identity) => Ok(identity),
            None => Err(anyhow!("Identity not found")),
        }
    }
}

//------------------------------------------------------------------------------

pub use subxt::utils::AccountId32 as AccountId;

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    JudgementRequested(AccountId, HashSet<Id>),
}

pub type Id = (IdKey, IdValue);

// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct Id(pub IdKey, pub IdValue);

// TODO: Add PgpFingerprint
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IdKey {
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

pub type IdValue = String;

fn decode_identity_info(fields: api::IdentityInfo) -> HashSet<Id> {
    use IdKey::*;
    let mut ids = HashSet::new();
    decode_identity_field_into(Display, fields.display, &mut ids);
    decode_identity_field_into(Legal, fields.legal, &mut ids);
    decode_identity_field_into(Web, fields.web, &mut ids);
    decode_identity_field_into(Matrix, fields.matrix, &mut ids);
    decode_identity_field_into(Email, fields.email, &mut ids);
    decode_identity_field_into(Image, fields.image, &mut ids);
    decode_identity_field_into(Twitter, fields.twitter, &mut ids);
    decode_identity_field_into(Github, fields.github, &mut ids);
    decode_identity_field_into(Discord, fields.discord, &mut ids);
    ids
}

fn decode_identity_field_into(key: IdKey, value: api::Data, ids: &mut HashSet<Id>) {
    if let Some(s) = decode_string_data(value) {
        ids.insert((key, s));
    }
}

fn decode_string_data(d: api::Data) -> Option<String> {
    use api::Data::*;
    match d {
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