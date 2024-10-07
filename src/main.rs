mod substrate;
mod chain;
mod node;
mod repo;
mod matrix;

use anyhow::Result;
use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

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

    tokio::spawn(async move { client.fetch_incoming_events(&tx).await.unwrap(); });

    while let Some(event) = rx.recv().await {
        repo::handle_chain_event(event).await?;
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
