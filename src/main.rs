mod api;
mod matrix;
mod node;
mod token;
mod config;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::api::{spawn_ws_serv,spawn_node_listener};
use crate::config::{GLOBAL_CONFIG, Config};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_line_number(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_from(&config_path)?;
    GLOBAL_CONFIG.set(config).expect("GLOBAL_CONFIG already initialized");

    info!("Starting services...");

    // Spawn node listener first
    info!("Spawning node listener...");
    spawn_node_listener().await?;
    info!("Node listener spawned successfully");

    //info!("Spawning matrix bot...");
    //matrix::start_bot().await?;
    //info!("Matrix bot spawned successfully");

    // Spawn websocket server
    info!("Spawning websocket server...");
    spawn_ws_serv().await;

    info!("Services closed!");
    Ok(())

}
