mod adapter;
mod api;
mod config;
mod node;
mod runner;
mod token;

use anyhow::{Context as _, Result};
use api::spawn_http_serv;
use std::panic;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{
    adapter::{dns::watch_dns, mail::watch_mailserver, matrix},
    api::{spawn_node_listener, spawn_redis_subscriber, spawn_ws_serv, RedisConnection},
    config::{Config, GLOBAL_CONFIG},
};

fn setup_logging() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "w3registrar=info,\
             matrix_sdk=error,\
             matrix_sdk_crypto=error,\
             matrix_sdk_base=error,\
             ruma_common::push=error",
        )
    });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        //.with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))
}

fn setup_panic_handler() {
    panic::set_hook(Box::new(|panic_info| {
        if let Some(location) = panic_info.location() {
            error!(
                "Panic occurred in file '{}' at line {}: {}",
                location.file(),
                location.line(),
                panic_info
            );
        } else {
            error!("Panic occurred: {}", panic_info);
        }
    }));
}

async fn check_required_services(config: &Config) -> (bool, bool, bool) {
    let needs_email = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"email".to_string()));

    let needs_matrix_bot = config.registrar.networks.values().any(|r| {
        r.fields.contains(&"matrix".to_string())
            || r.fields.contains(&"discord".to_string())
            || r.fields.contains(&"twitter".to_string())
    });

    let needs_web = config
        .registrar
        .networks
        .values()
        .any(|r| r.fields.contains(&"web".to_string()));

    (needs_email, needs_matrix_bot, needs_web)
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialize panic and logging handlers
    setup_panic_handler();
    setup_logging()?;

    info!("starting w3registrar...");

    // load configuration
    let config =
        Config::set_global_config().context("failed to load and set global configuration")?;

    // init redis conn pool
    RedisConnection::initialize_pool(&config.redis)?;

    // initialize runner
    let mut runner = runner::Runner::new();
    info!("initialized task runner");

    // start core services (these can have multiple instances)
    info!("starting core services...");
    runner.spawn(spawn_redis_subscriber, None).await;
    runner.spawn(spawn_node_listener, None).await;
    runner.spawn(spawn_ws_serv, None).await;
    runner.spawn(spawn_http_serv, None).await;

    // check and start singleton services
    let (needs_email, needs_matrix_bot, needs_web) = check_required_services(&config).await;

    if needs_email {
        info!("starting email service...");
        runner.spawn(watch_mailserver, Some("email_service")).await;
    }

    if needs_matrix_bot {
        info!("starting matrix bot service...");
        runner
            .spawn(matrix::start_bot, Some("matrix_service"))
            .await;
    }

    if needs_web {
        info!("starting dns watch service...");
        runner.spawn(watch_dns, Some("dns_service")).await;
    }

    info!("all services started successfully");

    // run until interrupted
    runner.run().await;

    // if we get here, we're shutting down
    info!("initiating graceful shutdown...");

    Ok(())
}
