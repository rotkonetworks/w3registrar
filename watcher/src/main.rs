use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use subxt::{OnlineClient, SubstrateConfig};
use subxt::utils::H256;

use std::fs;

#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod substrate {}

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

    println!("Block {}:\n", block.header().number);

    let events = block.events().await?;
    for event in events.iter() {
        let event = event?;
        if let Ok(e) = event.as_root_event::<substrate::Event>() {
            println!("{:?}\n", e);
        } else {
            println!("<Cannot decode event>");
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
