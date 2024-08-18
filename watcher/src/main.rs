mod substrate;

use substrate::Event;
use substrate::runtime_types::pallet_identity::pallet::Event as IdentityEvent;

use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use subxt::{OnlineClient, SubstrateConfig};
use subxt::utils::H256;

use std::fs;

type Client = OnlineClient<SubstrateConfig>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load()?;
    run(&config.endpoint).await
}

async fn run(url: &str) -> Result<()> {
    let client = Client::from_url(url).await?;

    // Get block 96
    // TODO: Figure out how to properly construct block hashes of the right type.

    let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
    let block = client.blocks().at(hash).await?;

    let events = block.events().await?;
    for event in events.iter() {
        let event = event?;
        if let Ok(event) = event.as_root_event::<Event>() {
            handle_event(&client, event).await?;
        }
    }

    Ok(())
}

async fn handle_event(client: &OnlineClient<SubstrateConfig>, event: Event) -> Result<()> {
    match event {
        Event::Identity(e) => {
            use IdentityEvent::*;
            match e {
                JudgementRequested { who, .. } => {
                    let query = substrate::storage()
                        .system()
                        .account(&who);

                    let account = client
                        .storage()
                        .at_latest()
                        .await?
                        .fetch(&query)
                        .await?;

                    if let Some(account) = account {
                        print!("{:#?}", account);
                    }
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
