mod matrix;
mod node;
mod repo;
mod config;

use anyhow::Result;
use node::Event;
use subxt::{OnlineClient, SubstrateConfig};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use config::{Config, WatcherConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    run_watcher(config.watcher).await?;

    Ok(())
}

async fn run_watcher(cfg: WatcherConfig) -> Result<()> {
    let client = node::Client::from_url(cfg.endpoint.as_str()).await?;

    let event_stream = node::subscribe_to_identity_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(event_res) = event_stream.next().await {
        use node::IdentityEvent::*;

        let event = event_res?;
        match event {
            | IdentitySet { who }
            | IdentityCleared { who, .. }
            | IdentityKilled { who, .. } => {
                println!("Identity changed for {}", who);
            }
            JudgementRequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &who).await?;
                    // TODO: Clean this up.
                    let has_paid_fee = reg.judgements.0.iter()
                        .any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));
                    if has_paid_fee {
                        println!("Judgement requested by {}: {:#?}", who, reg.info);
                    }
                }
            }
            JudgementUnrequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    println!("Judgement unrequested by {}", who);
                }
            }
            JudgementGiven(who, ri) => {
                if ri == cfg.registrar_index {
                    let reg = node::get_registration(&client, &who).await?;
                    if let Some(judgement) = reg.last_judgement() {
                        println!("Judgement given to {}: {:?}", who, judgement);
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

async fn run_watcher(cfg: WatcherConfig) -> Result<()> {
    let client = node::Client::from_url(cfg.endpoint.as_str()).await?;
    let client_clone = client.clone();

    let (tx, mut rx) = mpsc::channel(100);

    tokio::spawn(event_listener(tx, client));

    manage_events(&mut rx, cfg, client_clone).await
}
