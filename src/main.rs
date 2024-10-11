mod matrix;
mod node;

use std::fs;
use anyhow::anyhow;
use serde::Deserialize;
use tokio_stream::StreamExt;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    // pub matrix: matrix::Config,
    watcher: WatcherConfig,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct WatcherConfig {
    endpoint: String,
    registrar_index: node::RegistrarIndex,
    keystore_path: String,
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
    run_watcher(config.watcher).await?;

    Ok(())
}

async fn run_watcher(cfg: WatcherConfig) -> anyhow::Result<()> {
    let client = node::Client::from_url(cfg.endpoint.as_str()).await?;

    let event_stream = node::subscribe_to_identity_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(event_res) = event_stream.next().await {
        use node::IdentityEvent::*;

        let event = event_res?;
        match event {
            IdentitySet { who } | IdentityCleared { who, .. } | IdentityKilled { who, .. } => {
                println!("Identity changed for {}", who);
            }
            JudgementRequested {
                who,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &who).await?;
                    // TODO: Clean this up.
                    let has_paid_fee = reg
                        .judgements
                        .0
                        .iter()
                        .any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));
                    if has_paid_fee {
                        println!("Judgement requested by {}: {:#?}", who, reg.info);
                    }
                }
            }
            JudgementUnrequested {
                who,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    println!("Judgement unrequested by {}", who);
                }
            }
            JudgementGiven {
                target,
                registrar_index,
            } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &target).await?;
                    // TODO: Clean this up.
                    if let Some(judgement) = reg.judgements.0.last().map(|(j, _)| *j) {
                        println!("Judgement given to {}: {:?}", target, judgement);
                    }
                }
            }
            _ => {
                println!("{:?}", event);
            }
        }
    }

    Ok(())
}
