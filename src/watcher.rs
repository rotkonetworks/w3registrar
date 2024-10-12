// watcher.rs

use crate::api::ws::WebSocketServer;
use crate::signer::Signer;
use crate::node::{self, get_filled_fields};
use std::sync::Arc;
use serde::Deserialize;
use tokio_stream::StreamExt;
use tracing::{info, warn};
use subxt::utils::AccountId32 as AccountId;

pub type RegistrarIndex = u32;

#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(
    cfg: WatcherConfig,
    client: Arc<node::Client>,
    ws_server: Arc<WebSocketServer>,
    signer: Arc<Signer>,
) -> anyhow::Result<()> {
    let mut event_stream = node::subscribe_to_identity_events(&client).await?;
    while let Some(event_res) = event_stream.next().await {
        use node::IdentityEvent::*;

        let event = event_res?;
        match event {
            JudgementRequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    handle_judgement_request(&client, &ws_server, &signer, &who).await?;
                }
            }
            JudgementUnrequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    info!("Judgement unrequested by {:?}", who);
                    ws_server.cancel_challenges(&who).await?;
                }
            }
            JudgementGiven { target, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &target).await?;
                    if let Some(judgement) = reg.judgements.0.last().map(|(_, j)| j) {
                        info!("Judgement given to {:?}: {:?}", target, judgement);
                        ws_server.finalize_verification(&target, judgement).await?;
                    }
                }
            }
            _ => {
                info!("Received event: {:?}", event);
            }
        }
    }

    Ok(())
}

async fn handle_judgement_request(
    client: &Arc<node::Client>,
    ws_server: &Arc<WebSocketServer>,
    signer: &Arc<Signer>,
    who: &AccountId,
) -> anyhow::Result<()> {
    let reg = node::get_registration(client, who).await?;

    let has_paid_fee = reg.judgements.0.iter().any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));

    if has_paid_fee {
        info!(
            "Judgement requested by {:?} with fee paid. Initiating challenges for filled fields.",
            who
        );
        let filled_fields = node::get_filled_fields(&reg.info);

        if filled_fields.is_empty() {
            warn!("No verifiable fields found for {:?}. Considering as 'Unknown'.", who);
            ws_server.finalize_verification(who, &node::Judgement::Unknown).await?;
        } else {
            for field in filled_fields {
                ws_server.initiate_challenge(who, &field).await?;
            }
        }
    } else {
        info!("Judgement requested by {:?} but fee not paid.", who);
    }

    Ok(())
}
