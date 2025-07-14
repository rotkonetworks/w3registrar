use jsonrpsee::{core::client::ClientT, ws_client::WsClientBuilder};
use sp_core::H256;
use tracing::info;

use crate::{
    api::Network,
    config::GLOBAL_CONFIG,
    node::{identity::events::JudgementGiven, Client as NodeClient},
    postgres::{IndexerState, PostgresConnection, RegistrationRecord},
};

pub async fn index_identities_on_chain(state: IndexerState) -> anyhow::Result<()> {
    let network = state.network;
    let index = state.last_block_index;
    navigate_identity_chain_from_block(index, network).await?;
    Ok(())
}

async fn navigate_identity_chain_from_block(
    start_block_index: i64,
    network: Network,
) -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(&network)
        .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))
        .unwrap();

    let client = NodeClient::from_url(&network_cfg.endpoint).await?;
    let current_block_index = client.blocks().at_latest().await?.number() as i64;

    let ws_client = WsClientBuilder::default()
        .build(&network_cfg.endpoint)
        .await
        .unwrap();

    let mut pog_connection = PostgresConnection::default().await?;

    for block_index in start_block_index..current_block_index {
        let block_hash: H256 = ws_client
            .request::<Option<H256>, _>("chain_getBlockHash", [block_index])
            .await
            .unwrap()
            .unwrap();

        match client.blocks().at(block_hash).await {
            Ok(block) => {
                if block_index % 50 == 0 {
                    info!(hash=?block_hash.to_string(), number=?block_index,"Block");
                }

                if let Ok(events) = block.events().await {
                    for event in events.iter() {
                        if let Ok(event) = event {
                            if let Ok(Some(event)) = event.as_event::<JudgementGiven>() {
                                if let Some(record) =
                                    RegistrationRecord::from_judgement(&event).await.unwrap()
                                {
                                    pog_connection
                                        .save_registration(&record, &block_hash, &block_index)
                                        .await
                                        .unwrap();
                                }

                                info!(registrar_index=?event.registrar_index, wallet_id=?event.target,"Event");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to get block #{}: {}", block_hash, e);
            }
        }

        if block_index % 50 == 0 {
            pog_connection
                .update_indexer_state(&network, &block_hash, &(block_index as i64))
                .await?;
        }
    }
    Ok(())
}
