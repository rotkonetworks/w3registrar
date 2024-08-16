use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use subxt::{OnlineClient, PolkadotConfig};

use std::fs;

#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod polkadot {}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load()?;

    let api = OnlineClient::<PolkadotConfig>::from_url(config.endpoint).await?;
    let events = api.events().at_latest().await?;
    for event in events.iter() {
        let event = event?;
        if let Ok(e) = event.as_root_event::<polkadot::Event>() {
            println!("{:?}", e);
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
