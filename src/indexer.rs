use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{error, info, info_span, instrument, Span};

use crate::{
    api::Network,
    config::Config,
    node::{events::process_identity_events, Client as NodeClient},
    postgres::{PostgresConnection, RegistrationQuery, RegistrationRecord},
};

#[derive(Clone)]
pub struct Indexer {
    span: Span,
}

impl Indexer {
    pub async fn new() -> anyhow::Result<Self> {
        let span = info_span!("indexer");

        Ok(Self { span })
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn index_identities(self, network: &Network) -> anyhow::Result<()> {
        let pg_conn = PostgresConnection::default().await?;
        let cfg = Config::load_static();
        match pg_conn.get_indexer_state(network).await {
            Ok(state) => {
                let network_cfg = cfg.registrar.require_network(network)?;

                let client = NodeClient::from_url(&network_cfg.endpoint).await?;

                let block_index = client.blocks().at_latest().await?.number();
                let block_hash = client.blocks().at_latest().await?.hash();

                if state.last_block_index != block_index as i64
                    || state.last_block_hash != block_hash
                {
                    info!(start_block_index=?block_index, end_block_index=?state.last_block_index, "filling missing blocks");
                    self.index_remaining_identities(network).await?;
                }
            }
            Err(e) => {
                error!(error=?e, "failed to get indexer state");
                info!("indexing all identities from first block");
                self.index_identities_from_start(network).await?;
            }
        }
        info!(network=?network, "finished indexing network");

        Ok(())
    }

    /// Indexes the missing identities found on chain but missing in db
    #[instrument(skip_all, parent = &self.span)]
    async fn index_remaining_identities(&self, network: &Network) -> anyhow::Result<()> {
        let cfg = Config::load_static();
        let network_cfg = cfg.registrar.require_network(network)?;

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
        let network_cfg = cfg.registrar.require_network(network)?;

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

    /// Index the latest block's events for a network
    /// This can be called periodically or for catch-up indexing
    #[instrument(skip_all, parent = &self.span)]
    pub async fn index_latest_events(&self, network: &Network) -> anyhow::Result<u32> {
        let cfg = Config::load_static();
        let network_cfg = cfg.registrar.require_network(network)?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let block = client.blocks().at_latest().await?;
        let block_number = block.number();
        let block_hash = block.hash();

        // Get events
        let events = block.events().await?;

        // Process identity events using shared processor
        let block_hash_hex = hex::encode(block_hash.0);
        let processed = process_identity_events(&events, network, block_number, &block_hash_hex).await;

        if !processed.is_empty() {
            info!(
                network = %network,
                block = block_number,
                events = processed.len(),
                "indexed events from latest block"
            );
        }

        Ok(processed.len() as u32)
    }

    /// Backfill events from the last N blocks concurrently
    /// Uses shared client connections and parallel streams for speed
    #[instrument(skip_all, parent = &self.span)]
    pub async fn backfill_events(&self, network: &Network, num_blocks: u32) -> anyhow::Result<u32> {
        use futures::stream::{self, StreamExt};

        const MAX_CONCURRENT: usize = 100; // Process up to 100 blocks concurrently
        const NUM_CLIENTS: usize = 5; // Use 5 client connections

        let cfg = Config::load_static();
        let network_cfg = cfg.registrar.require_network(network)?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let latest = client.blocks().at_latest().await?;
        let latest_number = latest.number();
        let target_number = latest_number.saturating_sub(num_blocks);

        let total_events = Arc::new(AtomicU32::new(0));

        info!(
            network = %network,
            start = target_number,
            end = latest_number,
            blocks = num_blocks,
            "backfilling identity events"
        );

        // Collect block hashes by walking backwards
        let mut block_hashes = Vec::with_capacity(num_blocks as usize);
        let mut current_hash = latest.hash();
        let mut current_number = latest_number;

        while current_number >= target_number {
            block_hashes.push((current_number, current_hash));

            let block = match client.blocks().at(current_hash).await {
                Ok(b) => b,
                Err(_) => break,
            };

            current_hash = block.header().parent_hash;
            if current_number == 0 {
                break;
            }
            current_number -= 1;
        }

        info!(
            network = %network,
            collected = block_hashes.len(),
            "collected block hashes, processing with {} concurrent workers",
            MAX_CONCURRENT
        );

        // Create a pool of clients to share across tasks
        let mut clients = Vec::with_capacity(NUM_CLIENTS);
        for _ in 0..NUM_CLIENTS {
            clients.push(Arc::new(NodeClient::from_url(&network_cfg.endpoint).await?));
        }

        // Process all blocks using buffered stream for true concurrency
        let network = network.clone();
        let total_events_clone = Arc::clone(&total_events);

        stream::iter(block_hashes.into_iter().enumerate())
            .map(|(idx, (block_num, block_hash))| {
                let client = Arc::clone(&clients[idx % NUM_CLIENTS]);
                let network = network.clone();
                let total_events = Arc::clone(&total_events_clone);

                async move {
                    let block = match client.blocks().at(block_hash).await {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                    let events = match block.events().await {
                        Ok(e) => e,
                        Err(_) => return,
                    };

                    let block_hash_hex = hex::encode(block_hash.0);
                    let processed =
                        process_identity_events(&events, &network, block_num, &block_hash_hex).await;

                    if !processed.is_empty() {
                        info!(
                            network = %network,
                            block = block_num,
                            events = processed.len(),
                            "indexed events from block"
                        );
                        total_events.fetch_add(processed.len() as u32, Ordering::Relaxed);
                    }
                }
            })
            .buffer_unordered(MAX_CONCURRENT)
            .collect::<Vec<_>>()
            .await;

        let final_count = total_events.load(Ordering::Relaxed);
        info!(
            network = %network,
            total_events = final_count,
            "backfill complete"
        );

        Ok(final_count)
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn index(self) -> anyhow::Result<()> {
        info!("starting indexer");

        let cfg = Config::load_static();
        for network in cfg.registrar.supported_networks() {
            let clone = self.clone();
            tokio::spawn(async move {
                // Index identities (current state)
                if let Err(e) = clone.clone().index_identities(&network).await {
                    error!(network=?network, error=?e, "failed to index identities");
                }

                // Backfill last 10000 blocks to catch any missed events
                if let Err(e) = clone.clone().backfill_events(&network, 10000).await {
                    error!(network=?network, error=?e, "failed to backfill events");
                }

                // Index latest events (the NodeListener handles real-time events going forward)
                if let Err(e) = clone.index_latest_events(&network).await {
                    error!(network=?network, error=?e, "failed to index latest events");
                }
            });
        }

        Ok(())
    }
}
