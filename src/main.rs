mod adapter;
mod api;
mod config;
mod email;
mod matrix;
mod node;
mod runner;
mod token;

use crate::adapter::dns::watch_dns;
use crate::api::{spawn_node_listener, spawn_redis_subscriber, spawn_ws_serv};
use crate::config::{Config, GLOBAL_CONFIG};
use crate::email::watch_mailserver;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,matrix_sdk=warn,matrix_sdk_crypto=warn,matrix_sdk_base=warn")
    });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_line_number(true)
        .init();

    let config = Config::set_global_config()?;

    // Start services
    info!("Starting services...");
    let mut runner = runner::Runner::default();

    runner
        .push(tokio::spawn({
            let redis_config = config.redis.clone();
            async move {
                if let Err(e) = spawn_redis_subscriber(redis_config).await {
                    error!("Redis subscriber error: {}", e);
                }
            }
        }))
        .await;

    // init node connections
    runner
        .push(tokio::spawn(async move {
            info!("Spawning node listener...");
            if let Err(e) = spawn_node_listener().await {
                error!("Node listener error: {}", e);
            }
        }))
        .await;

    runner
        .push(tokio::spawn(async move {
            info!("Spawning websocket server...");
            if let Err(e) = spawn_ws_serv().await {
                error!("WebSocket server error: {}", e);
            }
        }))
        .await;

    // mail watcher
    let needs_email = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"email".to_string()));

    if needs_email {
        runner
            .push(tokio::spawn(async move {
                info!("Spawning mailserver...");
                if let Err(e) = watch_mailserver().await {
                    error!("Mailserver watcher error: {}", e);
                    return;
                } else {
                    info!("Mailserver watcher is exiting");
                }
            }))
            .await;
    }

    // matrix bot (spawn only once if *any* network needs matrix/discord/twitter)
    let needs_matrix_bot = config.registrar.networks.values().any(|r| {
        r.fields.contains(&"matrix".to_string())
            || r.fields.contains(&"discord".to_string())
            || r.fields.contains(&"twitter".to_string())
    });

    if needs_matrix_bot {
        runner
            .push(tokio::spawn(async move {
                info!("Spawning matrix bot...");
                if let Err(e) = matrix::start_bot().await {
                    error!("Matrix bot error: {}", e);
                }
            }))
            .await;
    }

    // web query
    let needs_web = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"web".to_string()));

    if needs_web {
        runner
            .push(tokio::spawn(async move {
                info!("Spawning DNS...");
                if let Err(e) = watch_dns().await {
                    error!("DNS watcher error: {}", e);
                    return;
                } else {
                    info!("DNS watcher is exiting");
                }
            }))
            .await;
    }

    runner.run().await;
    Ok(())
}
