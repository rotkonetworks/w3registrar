mod adapter;
mod api;
mod config;
mod node;
mod runner;
mod token;

use crate::adapter::dns::watch_dns;
use crate::adapter::{mail::watch_mailserver, matrix};
use crate::api::{spawn_node_listener, spawn_redis_subscriber, spawn_ws_serv};
use crate::config::{Config, GLOBAL_CONFIG};
use tracing::info;
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

    runner.push(spawn_redis_subscriber).await;
    runner.push(spawn_node_listener).await;
    runner.push(spawn_ws_serv).await;

    // mail watcher
    let needs_email = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"email".to_string()));

    if needs_email {
        runner.push(watch_mailserver).await;
    }

    // matrix bot (spawn only once if *any* network needs matrix/discord/twitter)
    let needs_matrix_bot = config.registrar.networks.values().any(|r| {
        r.fields.contains(&"matrix".to_string())
            || r.fields.contains(&"discord".to_string())
            || r.fields.contains(&"twitter".to_string())
    });

    if needs_matrix_bot {
        runner.push(matrix::start_bot).await;
    }

    // web query
    let needs_web = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"web".to_string()));

    if needs_web {
        runner.push(watch_dns).await;
    }

    runner.run().await;
    Ok(())
}
