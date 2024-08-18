mod chain;

use chain::identity::storage::types::identity_of::IdentityOf;
use chain::runtime_types::pallet_identity::types::Data;
use chain::Event;
use chain::runtime_types::pallet_identity::pallet::Event as IdentityEvent;

use anyhow::{anyhow, Result};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use subxt::{OnlineClient, SubstrateConfig};
use subxt::utils::{AccountId32, H256};

use std::fs;
use crate::chain::runtime_types::people_rococo_runtime::people::IdentityInfo;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load()?;
    let client = Client::from_url(config.endpoint).await?;
    let watcher = Watcher::new(client);

    watcher.process_events().await
}

//------------------------------------------------------------------------------

type Client = OnlineClient<SubstrateConfig>;

#[derive(Debug, Clone)]
struct Watcher {
    client: Client,
}

impl Watcher {
    fn new(client: Client) -> Self {
        Self { client}
    }

    async fn process_events(&self) -> Result<()> {
        // Get block 96
        // TODO: Figure out how to properly construct block hashes of the right type.

        let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
        let block = self.client.blocks().at(hash).await?;

        let events = block.events().await?;
        for event in events.iter() {
            let event = event?;
            if let Ok(event) = event.as_root_event::<Event>() {
                self.handle_event(event).await?;
            }
        }

        Ok(())
    }

    async fn handle_event(&self, event: Event) -> Result<()> {
        match event {
            Event::Identity(e) => {
                use IdentityEvent::*;
                match e {
                    JudgementRequested { who, .. } => {
                        let (reg, _) = self.fetch_identity_of(who).await?;
                        let info = reg.info;
                        println!("{:#?}\n", info);

                        let ids = decode_identity_info(info);
                        println!("{:?}", ids)
                    }
                    JudgementUnrequested { .. } => {}
                    JudgementGiven { .. } => {}
                    IdentitySet { .. } => {}
                    IdentityCleared { .. } => {}
                    IdentityKilled { .. } => {}
                    _ => {}
                };
            }
            _ => {}
        };

        Ok(())
    }
    
    async fn fetch_identity_of(&self, id: AccountId32) -> Result<IdentityOf> {
        let query = chain::storage()
            .identity()
            .identity_of(&id);

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

#[derive(Debug, Clone, PartialEq, Hash)]
struct Id(IdKey, String);

// TODO: Add PgpFingerprint
#[derive(Debug, Copy, Clone, PartialEq, Hash)]
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

fn decode_identity_info(info: IdentityInfo) -> Vec<Id> {
    use IdKey::*;
    let mut ids = vec![];
    decode_id_field_into(Display, info.display, &mut ids);
    decode_id_field_into(Legal, info.legal, &mut ids);
    decode_id_field_into(Web, info.web, &mut ids);
    decode_id_field_into(Matrix, info.matrix, &mut ids);
    decode_id_field_into(Email, info.email, &mut ids);
    decode_id_field_into(Image, info.image, &mut ids);
    decode_id_field_into(Twitter, info.twitter, &mut ids);
    decode_id_field_into(Github, info.github, &mut ids);
    decode_id_field_into(Discord, info.discord, &mut ids);
    ids
}

fn decode_id_field_into(key: IdKey, value: Data, ids: &mut Vec<Id>) {
    if let Some(s) = decode_string_data(value) {
        ids.push(Id(key, s));
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

//------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: u32,
    pub keystore_path: String,
}

impl Config {
    fn load() -> Result<Self> {
        let content = fs::read_to_string("config.toml")
            .map_err(|_| anyhow::anyhow!("Failed to open config at `config.toml`."))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
