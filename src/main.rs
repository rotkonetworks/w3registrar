// mod matrix;
mod watcher;
mod repo;
mod node;

use crate::repo::Database;

use anyhow::Result;
use serde::Deserialize;
use std::fs;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;

    let db = Database::open("/tmp/w3reg.sqlite").await?;

    watcher::process_block(
        &config.watcher,
        "0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65",
        &db
    ).await?;
    watcher::run(&config.watcher, &db).await?;

    Ok(())
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    // pub matrix: matrix::Config,
    pub watcher: watcher::Config,
}

impl Config {
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
