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

                        println!("display: {:?}", decode_string_data(info.display));
                        println!(" matrix: {:?}", decode_string_data(info.matrix));
                        println!("twitter: {:?}", decode_string_data(info.twitter));
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

fn decode_string_data(d: Data) -> Option<String> {
    match d {
        Data::Raw0(b) => Some(string_from_bytes(&b)),
        Data::Raw1(b) => Some(string_from_bytes(&b)),
        Data::Raw2(b) => Some(string_from_bytes(&b)),
        Data::Raw3(b) => Some(string_from_bytes(&b)),
        Data::Raw4(b) => Some(string_from_bytes(&b)),
        Data::Raw5(b) => Some(string_from_bytes(&b)),
        Data::Raw6(b) => Some(string_from_bytes(&b)),
        Data::Raw7(b) => Some(string_from_bytes(&b)),
        Data::Raw8(b) => Some(string_from_bytes(&b)),
        Data::Raw9(b) => Some(string_from_bytes(&b)),
        Data::Raw10(b) => Some(string_from_bytes(&b)),
        Data::Raw11(b) => Some(string_from_bytes(&b)),
        Data::Raw12(b) => Some(string_from_bytes(&b)),
        Data::Raw13(b) => Some(string_from_bytes(&b)),
        Data::Raw14(b) => Some(string_from_bytes(&b)),
        Data::Raw15(b) => Some(string_from_bytes(&b)),
        Data::Raw16(b) => Some(string_from_bytes(&b)),
        Data::Raw17(b) => Some(string_from_bytes(&b)),
        Data::Raw18(b) => Some(string_from_bytes(&b)),
        Data::Raw19(b) => Some(string_from_bytes(&b)),
        Data::Raw20(b) => Some(string_from_bytes(&b)),
        Data::Raw21(b) => Some(string_from_bytes(&b)),
        Data::Raw22(b) => Some(string_from_bytes(&b)),
        Data::Raw23(b) => Some(string_from_bytes(&b)),
        Data::Raw24(b) => Some(string_from_bytes(&b)),
        Data::Raw25(b) => Some(string_from_bytes(&b)),
        Data::Raw26(b) => Some(string_from_bytes(&b)),
        Data::Raw27(b) => Some(string_from_bytes(&b)),
        Data::Raw28(b) => Some(string_from_bytes(&b)),
        Data::Raw29(b) => Some(string_from_bytes(&b)),
        Data::Raw30(b) => Some(string_from_bytes(&b)),
        Data::Raw31(b) => Some(string_from_bytes(&b)),
        Data::Raw32(b) => Some(string_from_bytes(&b)),
        _ => None,
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
