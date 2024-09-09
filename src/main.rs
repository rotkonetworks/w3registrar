// mod matrix;
mod chain;
mod node;
mod registry;

use anyhow::Result;
use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

const TEST_BLOCK_HASH: &str = "0x512753ba6330e5d9e4932b88e2c39ba5f1a9a0c043be153e0a2070d6c4332c4c";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    run(config.watcher).await
}

async fn run(cfg: chain::ClientConfig) -> Result<()> {
    let client = chain::Client::from_config(cfg).await?;

    let (tx, mut rx) = mpsc::channel(100);

    client.fetch_events_in_block(TEST_BLOCK_HASH, &tx).await?;
    tokio::spawn(async move { client.fetch_incoming_events(&tx).await.unwrap(); });

    while let Some(event) = rx.recv().await {
        println!("{:#?}\n", event);
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    // pub matrix: matrix::Config,
    pub watcher: chain::ClientConfig,
}

impl Config {
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
