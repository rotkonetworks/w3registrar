use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use std::fs;
use serde::Deserialize;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load()?;

    tracing_subscriber::fmt()
        .with_max_level(config.log_level
            .parse::<Level>()
            .expect("Failed to parse log level"))
        .with_span_events(FmtSpan::CLOSE)
        .init();

    tracing::info!("{:#?}", config);

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub log_level: String,
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
