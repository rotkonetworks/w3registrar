use crate::node;
use crate::api::ws::WebSocketServer;
use std::sync::Arc;
use serde::Deserialize;
use tokio_stream::StreamExt;
use tracing::{info, warn};

pub type RegistrarIndex = u32;

#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: WatcherConfig, client: Arc<node::Client>, ws_server: Arc<WebSocketServer>) -> anyhow::Result<()> {
    let event_stream = node::subscribe_to_identity_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(event_res) = event_stream.next().await {
        use node::IdentityEvent::*;

        let event = event_res?;
        match event {
            JudgementRequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    handle_judgement_request(&client, &ws_server, &who).await?;
                }
            }
            JudgementUnrequested { who, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    info!("Judgement unrequested by {}", who);
                    ws_server.cancel_challenges(&who).await?;
                }
            }
            JudgementGiven { target, registrar_index } => {
                if registrar_index == cfg.registrar_index {
                    let reg = node::get_registration(&client, &target).await?;
                    if let Some(judgement) = reg.judgements.0.last().map(|(_, j)| j) {
                        info!("Judgement given to {}: {:?}", target, judgement);
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

async fn handle_judgement_request(client: &Arc<node::Client>, ws_server: &Arc<WebSocketServer>, who: &str) -> anyhow::Result<()> {
    let reg = node::get_registration(client, who).await?;
    
    let has_paid_fee = reg.judgements.0.iter().any(|(_, j)| matches!(j, node::Judgement::FeePaid(_)));
    
    if has_paid_fee {
        info!("Judgement requested by {} with fee paid. Initiating challenges for filled fields.", who);
        let filled_fields = get_filled_fields(&reg.info);
        
        if filled_fields.is_empty() {
            warn!("No verifiable fields found for {}. Considering as 'Unknown'.", who);
            ws_server.finalize_verification(who, &node::Judgement::Unknown).await?;
        } else {
            for field in filled_fields {
                ws_server.initiate_challenge(who, &field).await?;
            }
        }
    } else {
        info!("Judgement requested by {} but fee not paid.", who);
    }

    Ok(())
}

fn get_filled_fields(info: &node::IdentityInfo) -> Vec<String> {
    let mut filled_fields = Vec::new();

    // double check these field namings to be correct
    if !info.display.is_empty() { filled_fields.push("display".to_string()); }
    if !info.email.is_empty() { filled_fields.push("email".to_string()); }
    if !info.matrix.is_empty() { filled_fields.push("matrix".to_string()); }
    if !info.discord.is_empty() { filled_fields.push("discord".to_string()); }
    if !info.twitter.is_empty() { filled_fields.push("twitter".to_string()); }

    // Check for additional fields
    for (key, value) in &info.additional {
        if !value.is_empty() {
            filled_fields.push(key.clone());
        }
    }

    filled_fields
}
