mod chain;
mod repo;
mod matrix;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::fs;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use crate::chain::{Event, RegistrarIndex};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    run_watcher(config.watcher).await
}

async fn run_watcher(cfg: WatcherConfig) -> Result<()> {
    let client = chain::Client::from_url(cfg.endpoint.as_str()).await?;
    let client_clone = client.clone();

    let (tx, mut rx) = mpsc::channel(100);

    tokio::spawn(async move { client.fetch_incoming_events(&tx).await.unwrap(); });

    while let Some(event) = rx.recv().await {
        match event {
            Event::Other => {}
            Event::IdentityChanged(who) => {
                println!("Identity changed for {}", who);
            }
            Event::JudgementRequested(who, ri) => {
                if ri == cfg.registrar_index {
                    let reg = client_clone.get_registration(&who).await?;
                    if reg.has_paid_fee() {
                        println!("Judgement requested by {}: {:#?}", who, reg.identity);
                    }
                }
            }
            Event::JudgementUnrequested(who, ri) => {
                if ri == cfg.registrar_index {
                    println!("Judgement unrequested by {}", who);
                }
            }
            Event::JudgementGiven(who, ri) => {
                if ri == cfg.registrar_index {
                    let reg = client_clone.get_registration(&who).await?;
                    if let Some(judgement) = reg.last_judgement() {
                        println!("Judgement given to {}: {:?}", who, judgement);
                    }
                }
            }
        }
    }

    Ok(())
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    // pub matrix: matrix::Config,
    pub watcher: WatcherConfig,
}

#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

impl Config {
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}
