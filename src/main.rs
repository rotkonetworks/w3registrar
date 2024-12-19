mod api;
mod config;
mod matrix;
mod node;
mod token;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = config::Config::load_from("config.toml")?;
    api::spawn_services(config).await
}
