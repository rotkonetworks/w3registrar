use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use std::fs;
use w3registrar::{Config, challenger};

#[tokio::main]
async fn main() -> Result<()> {
    let config = open_config()?;
    
    tracing_subscriber::fmt()
        .with_max_level(config.log_level
            .parse::<Level>()
            .expect("Failed to parse log level"))
        .with_span_events(FmtSpan::CLOSE)
        .init();

    tracing::info!("Starting Matrix bot");
    challenger::start_bot(config.matrix).await?;
    
    Ok(())
}

fn open_config() -> Result<Config> {
    let content = fs::read_to_string("config.toml")
        .map_err(|_| anyhow::anyhow!("Failed to open config at `config.toml`."))?;
    
    toml::from_str::<Config>(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
}
