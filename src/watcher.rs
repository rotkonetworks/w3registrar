use crate::node;

use serde::Deserialize;
use tokio_stream::StreamExt;
use tracing::info;

pub type RegistrarIndex = u32;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let client = node::Client::from_url(cfg.endpoint.as_str()).await?;

    let event_stream = node::subscribe_to_identity_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(event_res) = event_stream.next().await {
        use node::IdentityEvent::*;

        let event = event_res?;
        match event {
            IdentitySet { who } | IdentityCleared { who, .. } | IdentityKilled { who, .. } => {
                info!("Identity changed for {}", who);
            }
            JudgementRequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &who).await?;
                    // TODO: Clean this up.
                    let has_paid_fee = reg
                        .judgements
                        .0
                        .iter()
                        .any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));
                    if has_paid_fee {
                        info!("Judgement requested by {}: {:#?}", who, reg.info);
                    }
                }
            }
            JudgementUnrequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    info!("Judgement unrequested by {}", who);
                }
            }
            JudgementGiven { target, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &target).await?;
                    // TODO: Clean this up.
                    if let Some(judgement) = reg.judgements.0.last().map(|(j, _)| *j) {
                        info!("Judgement given to {}: {:?}", target, judgement);
                    }
                }
            }
            _ => {
                info!("{:?}", event);
            }
        }
    }

    Ok(())
}
