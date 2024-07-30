use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use tracing::{error, info};
use w3registrar::{Config, watcher::Watcher};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load("config.toml").expect("Failed to load configuration");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .with_span_events(FmtSpan::CLOSE)
        .init();

    info!("Starting watcher");
    let watcher = Watcher::new(&config.watcher).await?;

    info!("Printing pending judgements");
    if let Err(e) = watcher.print_pending_judgements().await {
        error!("Failed to print pending judgements: {}", e);
    }

    info!("Starting event listener");
    if let Err(e) = watcher.run().await {
        error!("Watcher failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
