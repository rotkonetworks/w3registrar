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
    let api = OnlineClient::<SubstrateConfig>::from_url(url).await?;

    // Get block 96
    // TODO: Figure out how to properly construct block hashes of the right type.

    let hash: H256 = "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65".parse()?;
    let block = api.blocks().at(hash).await?;

    let events = block.events().await?;
    for event in events.iter() {
        let event = event?;
        if let Ok(event) = event.as_root_event::<Event>() {
            if let Some(id_event) = match event {
                Event::Identity(e) => {
                    use IdentityEvent::*;
                    match e {
                        IdentitySet { .. } => Some(e),
                        IdentityCleared { .. } => Some(e),
                        IdentityKilled { .. } => Some(e),
                        JudgementRequested { .. } => Some(e),
                        JudgementUnrequested { .. } => Some(e),
                        JudgementGiven { .. } => Some(e),
                        _ => None,
                    }
                }
                _ => None
            } {
                println!("{:?}", id_event);
            }
        }
    }

    Ok(())
}

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
