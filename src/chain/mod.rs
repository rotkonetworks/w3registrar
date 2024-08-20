mod substrate;
mod api;

use api::Event;
use api::IdentityOf;
use api::Data;
use api::IdentityInfo;
use api::IdentityEvent;

use subxt::{OnlineClient, SubstrateConfig};
use subxt::utils::{AccountId32, H256};
use anyhow::anyhow;
use anyhow::Result;
use serde::Deserialize;

use std::collections::HashSet;

pub async fn run_watcher(config: Config) -> Result<()> {
    let client = Client::from_url(config.endpoint).await?;
    let watcher = Watcher::new(client);
    watcher.run().await
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: u32,
    pub keystore_path: String,
}

//------------------------------------------------------------------------------

pub type Client = OnlineClient<SubstrateConfig>;

#[derive(Debug, Clone)]
pub struct Watcher {
    client: Client,
}

impl Watcher {
    pub fn new(client: Client) -> Self {
        Self { client}
    }

    pub async fn run(&self) -> Result<()> {
        // Get block 96
        // TODO: Figure out how to properly construct block hashes of the right type.

        let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
        let block = self.client.blocks().at(hash).await?;

        let events = block.events().await?;
        for event in events.iter() {
            if let Ok(event) = event?.as_root_event::<Event>() {
                self.handle_event(event).await?;
            }
        }

        Ok(())
    }

    async fn handle_event(&self, event: Event) -> Result<()> {
        match event {
            Event::Identity(e) => self.handle_identity_event(e).await,
            _ => Ok(()),
        }
    }

    async fn handle_identity_event(&self, event: IdentityEvent) -> Result<()> {
        use IdentityEvent::*;
        match event {
            JudgementRequested { who, .. } => {
                let (reg, _) = self.fetch_identity_of(&who).await?;
                let info = reg.info;
                let ids = decode_identity_info(info);
                let req = JudgementRequest::new(who, ids);

                println!("{:#?}", req);
            }
            JudgementUnrequested { .. } => {}
            JudgementGiven { .. } => {}
            IdentitySet { .. } => {}
            IdentityCleared { .. } => {}
            IdentityKilled { .. } => {}
            _ => {}
        };
        Ok(())
    }

    async fn fetch_identity_of(&self, id: &AccountId32) -> Result<IdentityOf> {
        let query = api::storage()
            .identity()
            .identity_of(id);

        let identity = self.client
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

#[derive(Debug, Clone, PartialEq)]
struct JudgementRequest {
    who: AccountId32,
    ids: HashSet<Id>,
}

impl JudgementRequest {
    fn new(who: AccountId32, ids: HashSet<Id>) -> Self {
        Self { who, ids }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Id(IdKey, IdValue);

// TODO: Add PgpFingerprint
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum IdKey {
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

type IdValue = String;

fn decode_identity_info(fields: IdentityInfo) -> HashSet<Id> {
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

fn decode_identity_field_into(key: IdKey, value: Data, ids: &mut HashSet<Id>) {
    if let Some(s) = decode_string_data(value) {
        ids.insert(Id(key, s));
    }
}

fn decode_string_data(d: Data) -> Option<String> {
    use Data::*;
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