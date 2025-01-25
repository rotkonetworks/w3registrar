mod api;
mod config;
mod email;
mod matrix;
mod node;
mod token;

use crate::api::{spawn_node_listener, spawn_ws_serv, spawn_redis_subscriber};
use crate::config::{Config, GLOBAL_CONFIG};
use crate::email::watch_mailserver;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_line_number(true)
        .with_target(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    // Load configuration
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_from(&config_path)?;
    GLOBAL_CONFIG
        .set(config.clone())
        .expect("GLOBAL_CONFIG already initialized");

    // Start services
    info!("Starting services...");
    let mut handles = Vec::new();

    // TODO: rm spawned services config
    if config.spawned_services.redis {
        handles.push(tokio::spawn(async move {
            if let Err(e) = spawn_redis_subscriber(config.redis.clone()).await {
                error!("Redis subscriber error: {}", e);
            }
        }));
    }

    if config.spawned_services.matrix {
        handles.push(tokio::spawn(async move {
            info!("Spawning matrix bot...");
            if let Err(e) = matrix::start_bot().await {
                error!("Matrix bot error: {}", e);
            }
        }));
    }

    if config.spawned_services.nodelistener {
        handles.push(tokio::spawn(async move {
            info!("Spawning node listener...");
            if let Err(e) = spawn_node_listener().await {
                error!("Node listener error: {}", e);
            }
        }));
    }

    if config.spawned_services.websocket {
        handles.push(tokio::spawn(async move {
            info!("Spawning websocket server...");
            if let Err(e) = spawn_ws_serv().await {
                error!("WebSocket server error: {}", e);
            }
        }));
    }

    if config.spawned_services.email {
        handles.push(tokio::spawn(async move {
            info!("Spawning mailserver...");
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

    // signal handling and exit
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            std::process::exit(0);
        }
        _ = futures::future::join_all(handles) => {
            info!("All services completed");
        }
    }

    Ok(())
}
