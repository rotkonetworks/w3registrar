mod matrix;
mod node;
mod registry;

use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use std::fs;
use crate::node::{Command, Judgement};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    let client = node::Client::from_config(config.watcher).await?;

    fetch_events(&client).await?;
    provide_judgements(&client).await?;

    Ok(())
}

async fn fetch_events(client: &node::Client) -> Result<()> {
    let events = client.fetch_events().await?;
    for event in events.into_iter() {
        registry::handle_node_event(event).await?;
    }
    Ok(())
}

async fn provide_judgements(client: &node::Client) -> Result<()> {
    let ids = registry::fetch_verified_identities().await?;
    for id in ids.into_iter() {
        client.exec(Command::ProvideJudgement(id.who, Judgement::Good)).await?;
    }
    Ok(())
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
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
