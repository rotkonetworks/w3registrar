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
    run_watcher(config.watcher).await
}

async fn event_listener(tx: Sender<Event>, client: OnlineClient<SubstrateConfig>) -> Result<()> {
    node::fetch_events(&client, &tx).await
}

async fn manage_events(
    rx: &mut Receiver<Event>,
    cfg: WatcherConfig,
    client: OnlineClient<SubstrateConfig>,
) -> Result<()> {
    while let Some(event) = rx.recv().await {
        use node::Event::*;
        match event {
            Other => {}
            IdentityChanged(who) => {
                println!("Identity changed for {}", who);
            }
            JudgementRequested(who, ri) => {
                if ri == cfg.registrar_index {
                    let reg = node::get_registration(&client, &who).await?;
                    if reg.has_paid_fee() {
                        println!("Judgement requested by {}: {:#?}", who, reg.identity);
                    }
                }
            }
            JudgementUnrequested(who, ri) => {
                if ri == cfg.registrar_index {
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
