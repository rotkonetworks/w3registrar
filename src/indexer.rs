use tracing::{error, info, info_span, instrument, Span};

use crate::{
    api::Network,
    config::GLOBAL_CONFIG,
    node::Client as NodeClient,
    postgres::{PostgresConnection, RegistrationQuery, RegistrationRecord},
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
                    self.index_remaining_identities(&network).await?;
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

    /// Indexes the missing identities found on chain but missing in db
    #[instrument(skip_all, parent = &self.span)]
    async fn index_remaining_identities(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(&network)
            .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;

        let mut pog_connection = PostgresConnection::default().await?;

        let mut iter = client
            .storage()
            .at_latest()
            .await?
            .iter(super::node::storage().identity().identity_of_iter())
            .await?;

        let mut chain_registrations = vec![];
        let query = RegistrationQuery::default();
        let db_registrations = pog_connection.search_registration_records(&query).await?;

        while let Some(Ok(identity)) = &iter.next().await {
            if let Some(record) =
                RegistrationRecord::from_storage_pairs(&identity, &network).await?
            {
                chain_registrations.push(record);
            }
        }

        let filtered: Vec<&RegistrationRecord> = chain_registrations
            .iter()
            .zip(db_registrations.iter())
            .filter(|(a, b)| a.wallet_id() != b.wallet_id())
            .filter_map(|(a, b)| {
                if a.wallet_id() != b.wallet_id() {
                    Some(a)
                } else {
                    None
                }
            })
            .collect();

        for record in filtered {
            pog_connection.save_registration(&record).await?;
        }

        Ok(())
    }

    /// Gets all on-chain identities untill now and saves them to db
    #[instrument(skip_all, parent = &self.span)]
    async fn index_identities_from_start(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(&network)
            .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))?;

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
            if let Some(record) =
                RegistrationRecord::from_storage_pairs(&identity, &network).await?
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
