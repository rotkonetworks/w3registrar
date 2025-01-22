mod api;
mod config;
mod email;
mod matrix;
mod node;
mod token;

use crate::api::{spawn_node_listener, spawn_ws_serv};
use crate::config::{Config, GLOBAL_CONFIG};
use crate::email::watch_mailserver;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use crate::api::spawn_redis_subscriber;

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
    GLOBAL_CONFIG
        .set(config.clone())
        .expect("GLOBAL_CONFIG already initialized");

    info!("Starting services...");
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let mut handles = Vec::new();

    if config.spawned_services.redis {
        let shutdown_rx = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            if let Err(e) = spawn_redis_subscriber(config.redis.clone(), shutdown_rx).await {
                error!("Redis subscriber error: {}", e);
            }
        }));
    }

    if config.spawned_services.matrix {
        let shutdown_rx = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Spawning matrix bot...");
            if let Err(e) = matrix::start_bot(shutdown_rx).await {
                error!("Matrix bot error: {}", e);
            }
        }));
    }

    if config.spawned_services.nodelistener {
        let shutdown_rx = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Spawning node listener...");
            if let Err(e) = spawn_node_listener(shutdown_rx).await {
                error!("Node listener error: {}", e);
            }
        }));
    }

    if config.spawned_services.websocket {
        let shutdown_rx = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Spawning websocket server...");
            if let Err(e) = spawn_ws_serv(shutdown_rx).await {
                error!("WebSocket server error: {}", e);
            }
        }));
    }

    if config.spawned_services.email {
        let shutdown_rx = shutdown_tx.subscribe();
        handles.push(tokio::spawn(async move {
            info!("Spawning mailserve...");
            if let Err(e) = watch_mailserver().await {
                error!("Mailserver error: {}", e);
            }
        }));
    }
    if handles.is_empty() {
        error!("No services were configured to run!");
        return Ok(());
    }

    info!("All configured services spawned successfully");

    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping services...");

    let _ = shutdown_tx.send(());

    let shutdown_timeout = tokio::time::Duration::from_secs(5);
    let all_tasks = futures::future::join_all(handles);

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
