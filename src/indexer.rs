use tracing::{error, info, info_span, instrument, Span};

use crate::{
    api::Network,
    config::Config,
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
        let pg_conn = PostgresConnection::default().await?;
        let cfg = Config::load_static();
        match pg_conn.get_indexer_state(network).await {
            Ok(state) => {
                let network_cfg = cfg
                    .registrar
                    .require_network(network)?;

                let client = NodeClient::from_url(&network_cfg.endpoint).await?;

                let block_index = client.blocks().at_latest().await?.number();
                let block_hash = client.blocks().at_latest().await?.hash();

                if state.last_block_index != block_index as i64
                    || state.last_block_hash != block_hash
                {
                    info!(start_block_index=?block_index, end_block_index=?state.last_block_index, "Filling missing blocks");
                    self.index_remaining_identities(network).await?;
                }
            }
            Err(e) => {
                error!(error=?e, "Failed to get indexer state");
                info!("Indexing all identities from first block");
                self.index_identities_from_start(network).await?;
            }
        }
        info!(network=?network, "Finished indexing network");

        Ok(())
    }

    /// Indexes the missing identities found on chain but missing in db
    #[instrument(skip_all, parent = &self.span)]
    async fn index_remaining_identities(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = Config::load_static();
        let network_cfg = cfg
            .registrar
            .require_network(network)?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let mut pg_conn = PostgresConnection::default().await?;

        let mut iter = client
            .storage()
            .at_latest()
            .await?
            .iter(super::node::storage().identity().identity_of_iter())
            .await?;

        let mut chain_registrations = vec![];
        let db_registrations = pg_conn
            .search_registration_records(&RegistrationQuery::default())
            .await?;

        while let Some(Ok(identity)) = iter.next().await {
            if let Some(record) = RegistrationRecord::from_storage_pairs(&identity, network).await?
            {
                chain_registrations.push(record);
            }
        }

        // Find records on chain but not in db
        let db_wallets: std::collections::HashSet<_> =
            db_registrations.iter().map(|r| r.wallet_id()).collect();

        for record in chain_registrations
            .iter()
            .filter(|r| !db_wallets.contains(&r.wallet_id()))
        {
            pg_conn.save_registration(record).await?;
        }

        Ok(())
    }

    /// Gets all on-chain identities and saves them to db
    #[instrument(skip_all, parent = &self.span)]
    async fn index_identities_from_start(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = Config::load_static();
        let network_cfg = cfg
            .registrar
            .require_network(network)?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let mut pg_conn = PostgresConnection::default().await?;

        let block = client.blocks().at_latest().await?;
        let block_index = block.number();
        let block_hash = block.hash();

        let mut iter = client
            .storage()
            .at_latest()
            .await?
            .iter(super::node::storage().identity().identity_of_iter())
            .await?;

        while let Some(Ok(identity)) = iter.next().await {
            if let Some(record) = RegistrationRecord::from_storage_pairs(&identity, network).await?
            {
                pg_conn.save_registration(&record).await?;
            }
        }

        pg_conn
            .update_indexer_state(network, &block_hash, &(block_index as i64))
            .await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn index(self) -> anyhow::Result<()> {
        info!("Starting indexer");

        let cfg = Config::load_static();
        for network in cfg.registrar.supported_networks() {
            let clone = self.clone();
            tokio::spawn(async move {
                if let Err(e) = clone.index_identities(&network).await {
                    error!(network=?network, error=?e, "Failed to index identities");
                }
            });
        }

        Ok(())
    }
}
