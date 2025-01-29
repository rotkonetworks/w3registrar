mod api;
mod config;
mod email;
mod matrix;
mod node;
mod token;

use crate::api::{spawn_node_listener, spawn_redis_subscriber, spawn_ws_serv};
use crate::config::{Config, GLOBAL_CONFIG};
use crate::email::watch_mailserver;
use tokio::time::Duration;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new("info,matrix_sdk=warn,matrix_sdk_crypto=warn,matrix_sdk_base=warn")
        });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_line_number(true)
        .init();
    //tracing_subscriber::fmt()
    //    .with_max_level(Level::INFO)
    //    .with_line_number(true)
    //    .with_target(true)
    //    .with_span_events(FmtSpan::CLOSE)
    //    .init();

    // init global configs
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_from(&config_path)?;
    GLOBAL_CONFIG
        .set(config.clone())
        .expect("GLOBAL_CONFIG already initialized");

    // Start services
    info!("Starting services...");
    let mut handles = Vec::new();

    // init redis
    let redis_handle = tokio::spawn({
        let redis_config = config.redis.clone();
        async move {
            if let Err(e) = spawn_redis_subscriber(redis_config).await {
                error!("Redis subscriber error: {}", e);
            }
        }
    });
    handles.push(redis_handle);
    // increase cloud bills
    tokio::time::sleep(Duration::from_millis(100)).await;

    // init node connections
    handles.push(tokio::spawn(async move {
        info!("Spawning node listener...");
        if let Err(e) = spawn_node_listener().await {
            error!("Node listener error: {}", e);
        }
    }));

    // init api
    handles.push(tokio::spawn(async move {
        info!("Spawning websocket server...");
        if let Err(e) = spawn_ws_serv().await {
            error!("WebSocket server error: {}", e);
        }
    }));

    // mail watcher
    let needs_email = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"email".to_string()));

    if needs_email {
        handles.push(tokio::spawn(async move {
            info!("Spawning mailserver...");
            if let Err(e) = watch_mailserver().await {
                error!("Mailserver error: {}", e);
            }
        }));
    }

    // matrix bot (spawn only once if *any* network needs matrix/discord/twitter)
    let needs_matrix_bot = config.registrar.networks.values().any(|r| {
        r.fields.contains(&"matrix".to_string())
            || r.fields.contains(&"discord".to_string())
            || r.fields.contains(&"twitter".to_string())
    });

    if needs_matrix_bot {
        handles.push(tokio::spawn(async move {
            info!("Spawning matrix bot...");
            if let Err(e) = matrix::start_bot().await {
                error!("Matrix bot error: {}", e);
            }
        }));
    }

    info!("gl hf! All services spawned successfully");

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
