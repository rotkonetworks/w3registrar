mod config;
mod matrix;
mod node;

use anyhow::Result;
use config::{Config, WatcherConfig};
use tokio_stream::StreamExt;
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

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
