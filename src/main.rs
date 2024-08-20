mod matrix;
mod node;

use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;

    process_events(config.watcher).await
}

async fn process_events(client_config: node::ClientConfig) -> Result<()> {
    let client = node::Client::with_config(client_config).await?;

    let events = client.fetch_events().await?;
    for event in events.iter() {
        println!("{:#?}", event);
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    pub matrix: matrix::Config,
    pub watcher: node::ClientConfig,
}

impl Config {
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
