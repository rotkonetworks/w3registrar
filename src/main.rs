mod api;
mod config;
mod matrix;
mod node;
mod token;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::api::{spawn_node_listener, spawn_ws_serv};
use crate::config::{Config, GLOBAL_CONFIG};
use tracing::{error, info};

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
    GLOBAL_CONFIG
        .set(config)
        .expect("GLOBAL_CONFIG already initialized");

    info!("Starting services...");

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

    let matrix_handle = {
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            info!("Spawning matrix bot...");
            if let Err(e) = matrix::start_bot(shutdown_rx).await {
                error!("Matrix bot error: {}", e);
            }
        })
    };

    let node_handle = {
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            info!("Spawning node listener...");
            if let Err(e) = spawn_node_listener(shutdown_rx).await {
                error!("Node listener error: {}", e);
            }
        })
    };

    let ws_handle = {
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            info!("Spawning websocket server...");
            if let Err(e) = spawn_ws_serv(shutdown_rx).await {
                error!("WebSocket server error: {}", e);
            }
        })
    };

    info!("All services spawned successfully");

    // wait for kill signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping services...");

    let _ = shutdown_tx.send(());

    let shutdown_timeout = tokio::time::Duration::from_secs(5);

    let all_tasks = futures::future::join_all(vec![node_handle, matrix_handle, ws_handle]);

    match tokio::time::timeout(shutdown_timeout, all_tasks).await {
        Ok(results) => {
            for result in results {
                if let Err(e) = result {
                    error!("Task join error: {}", e);
                }
            }
            info!("All services stopped gracefully");
        }
        Err(_) => {
            error!(
                "Shutdown timeout reached after {} seconds, forcing exit",
                shutdown_timeout.as_secs()
            );
        }
    }

    Ok(())
}
