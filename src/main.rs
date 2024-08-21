mod matrix;
mod node;
mod registry;

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

    run_watcher(config.watcher).await
}

async fn run_watcher(config: WatcherConfig) -> Result<()> {
    let client = node::Client::from_url(config.endpoint.as_str()).await?;

    let events = client.fetch_events().await?;
    for event in events.iter() {
        println!("{:#?}\n", event);

        match event {
            node::Event::JudgementRequested(who, _) => {
                let contact = client.fetch_contact(who).await?;
                println!("{:#?}", contact);
            }
        }
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    pub matrix: matrix::Config,
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
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
