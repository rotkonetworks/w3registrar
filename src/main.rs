mod matrix;
mod node;
mod watcher;
mod api;
mod signer;

use std::fs;
use std::sync::Arc;
use anyhow::anyhow;
use serde::Deserialize;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tokio::signal;

use subxt::utils::AccountId32 as AccountId;

#[derive(Debug, Deserialize)]
struct Config {
    watcher: watcher::WatcherConfig,
    matrix: MatrixConfig,
    api: ApiConfig,
    signer: SignerConfig,
}

#[derive(Debug, Deserialize)]
struct MatrixConfig {
    homeserver: String,
    username: String,
    password: String,
    security_key: String,
    admins: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ApiConfig {
    http_port: u16,
    ws_port: u16,
}

#[derive(Debug, Deserialize)]
struct SignerConfig {
    proxy_account: String,
    registrar_account: String,
}

impl Config {
    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow!("Failed to open config `{}`.", path))?;
        toml::from_str(&content)
            .map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;

    let client = Arc::new(node::Client::from_url(&config.watcher.endpoint).await?);

    let signer = Arc::new(signer::Signer::new(
        client.clone(),
        &config.watcher.keystore_path,
        config.signer.proxy_account.parse()?,
        config.signer.registrar_account.parse()?,
    ).await?);

    let ws_server = Arc::new(api::WebSocketServer::new(
        client.clone(),
        config.watcher.registrar_index,
        signer.clone(),
    ));

    let ws_handle = {
        let ws_server = ws_server.clone();
        tokio::spawn(async move {
            if let Err(e) = ws_server.start(config.api.ws_port).await {
                tracing::error!("WebSocket server error: {:?}", e);
            }
        })
    };

    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watcher::run(config.watcher, client, ws_server, signer).await {
            tracing::error!("Watcher error: {:?}", e);
        }
    });

    signal::ctrl_c().await?;

    tracing::info!("Shutting down...");

    tokio::try_join!(ws_handle, watcher_handle)?;

    Ok(())
}
