mod api;
mod matrix;
mod node;
mod token;
mod config;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::api::{spawn_ws_serv,spawn_node_listener};
use crate::config::{GLOBAL_CONFIG, Config};
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_line_number(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_from(&config_path)?;
    GLOBAL_CONFIG.set(config).expect("GLOBAL_CONFIG already initialized");

    info!("Starting services...");
    
    // Spawn services as separate tasks
    let node_handle = tokio::spawn(async {
        info!("Spawning node listener...");
        if let Err(e) = spawn_node_listener().await {
            error!("Node listener error: {}", e);
        }
    });

    let matrix_handle = tokio::spawn(async {
        info!("Spawning matrix bot...");
        if let Err(e) = matrix::start_bot().await {
            error!("Matrix bot error: {}", e);
        }
    });

    let ws_handle = tokio::spawn(async {
        info!("Spawning websocket server...");
        spawn_ws_serv().await
    });

    info!("All services spawned successfully");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping services...");

    // Cancel all tasks
    node_handle.abort();
    matrix_handle.abort();
    ws_handle.abort();

    // Wait for tasks to finish
    let _ = tokio::join!(node_handle, matrix_handle, ws_handle);
    
    info!("All services stopped gracefully");
    Ok(())
}
