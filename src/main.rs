mod matrix;
mod node;

use std::fs;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    // pub matrix: matrix::Config,
    pub watcher: WatcherConfig,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: node::RegistrarIndex,
    pub keystore_path: String,
}

impl Config {
    pub fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow!("Failed to open config `{}`.", path))?;
        toml::from_str(&content)
            .map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    run_watcher(config.watcher).await?;

    Ok(())
}

async fn run_watcher(cfg: WatcherConfig) -> Result<()> {
    let client = node::Client::from_url(cfg.endpoint.as_str()).await?;

    let event_stream = node::subscribe_to_identity_events(&client).await?;

    tokio::pin!(event_stream);

    node::event_manager(event_stream, cfg, client).await
}

