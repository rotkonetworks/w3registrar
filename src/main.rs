mod api;
mod matrix;
mod node;
mod token;
mod watcher;

use anyhow::anyhow;
use serde::Deserialize;
use std::fs;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use matrix::Config as MatrixConfig;
use watcher::Config as WatcherConfig;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    matrix: MatrixConfig,
    watcher: WatcherConfig,
}

impl Config {
    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let content =
            fs::read_to_string(path).map_err(|_| anyhow!("Failed to open config `{}`.", path))?;
        toml::from_str(&content).map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml").unwrap();
    api::spawn_services(config).await
}
