use jsonrpsee::{core::client::ClientT, ws_client::WsClientBuilder};
use sp_core::H256;
use tracing::{error, info, info_span, instrument, Span};

use crate::{
    api::Network,
    config::GLOBAL_CONFIG,
    node::{
        get_judgement, identity::events::JudgementGiven,
        runtime_types::pallet_identity::types::Judgement, Client as NodeClient,
    },
    postgres::{IndexerState, PostgresConnection, RegistrationRecord},
};

#[derive(Clone)]
pub struct Indexer {
    span: Span,
}

impl Indexer {
    pub async fn new() -> anyhow::Result<Self> {
        let span = info_span!("node_listener");

        Ok(Self { span })
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn index_identities(self, network: &Network) -> anyhow::Result<()> {
        let pog_connection = PostgresConnection::default().await?;
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        match pog_connection.get_indexer_state(network).await {
            Ok(state) => {
                let network_cfg = cfg
                    .registrar
                    .get_network(&network)
                    .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))
                    .unwrap();

                let client = NodeClient::from_url(&network_cfg.endpoint).await?;

                let block_index = client.blocks().at_latest().await?.number();
                let block_hash = client.blocks().at_latest().await?.hash();

                if state.last_block_index.ne(&(block_index as i64))
                    || state.last_block_hash.ne(&block_hash)
                {
                    info!(start_block_index=?block_index, end_block_index=?state.last_block_index, "Filling missing blocks");
                    self.index_remaining_identities(state).await?;
                }
            }
            Err(e) => {
                error!(error=?e,"ERROR");
                info!("Indexing all identities from the First block");
                self.index_identities_from_start(&network).await?;
            }
        }
        info!(network = ?network, "Finished indexing network");

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn index_remaining_identities(&self, state: IndexerState) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(&state.network)
            .ok_or_else(|| anyhow::anyhow!("Network {} not configured", state.network))
            .unwrap();

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;

        let current_block_index: i64 = client.blocks().at_latest().await?.number() as i64;

        let ws_client = WsClientBuilder::default()
            .build(&network_cfg.endpoint)
            .await
            .unwrap();

        let mut pog_connection = PostgresConnection::default().await?;

        for block_index in state.last_block_index..current_block_index {
            let block_hash: H256 = ws_client
                .request::<Option<H256>, _>("chain_getBlockHash", [block_index])
                .await
                .unwrap()
                .unwrap();

            match client.blocks().at(block_hash).await {
                Ok(block) => {
                    if block_index % 100 == 0 {
                        info!(hash=?block_hash.to_string(), number=?block_index,"Block");
                    }

                    // TODO: deal with ever ending nesting...
                    if let Ok(events) = block.events().await {
                        for event in events.iter() {
                            if let Ok(event) = event {
                                if let Ok(Some(jud)) = event.as_event::<JudgementGiven>() {
                                    if let Ok(Some(judgement)) =
                                        get_judgement(&jud.target, &state.network).await
                                    {
                                        if matches!(judgement, Judgement::Reasonable) {
                                            if let Some(record) =
                                                RegistrationRecord::from_judgement(&jud)
                                                    .await
                                                    .unwrap()
                                            {
                                                pog_connection
                                                    .save_registration(&record)
                                                    .await
                                                    .unwrap();
                                                info!(registrar_index=?jud.registrar_index, wallet_id=?jud.target,"`JudgementGiven` Event");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to get block #{}: {}", block_hash, e);
                }
            }
        }
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn index_identities_from_start(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(&network)
            .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))
            .unwrap();

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;

        let mut pog_connection = PostgresConnection::default().await?;

        let block_index = client.blocks().at_latest().await?.number();
        let block_hash = client.blocks().at_latest().await?.hash();

        let mut iter = client
            .storage()
            .at_latest()
            .await?
            .iter(super::node::storage().identity().identity_of_iter())
            .await?;

        // TODO: buffer every 50 or so request and then execute that at a one go, instead of
        // running one request at a time?
        while let Some(Ok(identity)) = &iter.next().await {
            if let Some(record) = RegistrationRecord::from_storage_pairs(&identity, &network)
                .await
                .unwrap()
            {
                pog_connection.save_registration(&record).await?;
            }
        }

        pog_connection
            .update_indexer_state(&network, &block_hash, &(block_index as i64))
            .await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn index(self) -> anyhow::Result<()> {
        info!("Starting indexer");

        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let networks = cfg.registrar.supported_networks();

        for network in networks {
            let clone = self.clone();
            tokio::spawn(async move {
                match clone.index_identities(&network).await {
                    Ok(_) => {}
                    Err(e) => error!(network=?network, error=?e, "Failed to index identities"),
                }
            });
        }

        Ok(())
    }
}
