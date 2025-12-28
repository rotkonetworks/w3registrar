//! Node event listener for processing blockchain events
//!
//! This module handles subscribing to finalized blocks and processing
//! identity-related events from the chain.

use crate::adapter::email::jmap::send_email_challenge;
use crate::api::{Account, AccountType, AccountVerification, Network};
use crate::config::{Config, RedisConfig};
use crate::node::{
    self,
    events::{is_judgement_given, is_judgement_requested, is_judgement_unrequested, process_identity_events},
    filter_accounts,
    substrate::runtime_types::pallet_identity::types::Judgement,
    Block, Client as NodeClient,
};
use crate::postgres::{PostgresConnection, RegistrationRecord};
use crate::redis::RedisConnection;
use crate::token::{AuthToken, Token};

use anyhow::anyhow;
use std::collections::HashMap;
use subxt::utils::AccountId32;
use tracing::{error, info, info_span, instrument, Span};

#[derive(Debug, Clone)]
pub struct NodeListener {
    clients: HashMap<Network, NodeClient>,
    redis_cfg: RedisConfig,
    span: Span,
}

impl NodeListener {
    pub async fn new() -> anyhow::Result<Self> {
        let cfg = Config::load_static();
        let mut clients = HashMap::new();

        for (network, network_cfg) in &cfg.registrar.networks {
            let client = NodeClient::from_url(&network_cfg.endpoint)
                .await
                .map_err(|e| anyhow!("failed to connect to {} network: {}", network, e))?;
            clients.insert(network.clone(), client);
        }
        let span = info_span!("node_listener");

        Ok(Self {
            span,
            clients,
            redis_cfg: cfg.redis.clone(),
        })
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_registration(
        &mut self,
        who: &AccountId32,
        index: u32,
        network: &Network,
    ) -> anyhow::Result<()> {
        let cfg = Config::load_static();

        let network_cfg = cfg.registrar.require_network(network)?;

        // Skip registration handling for inactive registrars (index-only mode)
        if !network_cfg.active {
            info!(network = %network, "skipping registration - registrar not active on this network");
            return Ok(());
        }

        if network_cfg.registrar_index != index {
            return Err(anyhow!(
                "invalid registrar index on network {network}, expected {} but got {index}",
                network_cfg.registrar_index
            ));
        }

        let client = self
            .clients
            .get(network)
            .ok_or_else(|| anyhow!("no client for network {}", network))?;

        let registration = node::get_registration(client, who).await?;
        let accounts = Account::into_accounts(&registration.info);

        crate::api::server::SocketListener::check_node(who.clone(), accounts.clone(), network)
            .await?;

        let mut conn = RedisConnection::get_connection().await?;
        conn.clear_all_related_to(network, who).await?;

        let filtered_accounts = filter_accounts(
            &registration.info,
            who,
            network_cfg.registrar_index,
            network,
        )
        .await?;

        let mut verification = AccountVerification::new(network.to_string());

        for (account, is_done) in &filtered_accounts {
            let (name, acc_type) = (account.inner(), account.account_type());
            let token = account.generate_token(*is_done).await;
            verification.add_challenge(&acc_type, name, token);
        }

        if matches!(cfg.adapter.email.protocol, crate::config::EmailProtocol::Jmap)
            && matches!(
                cfg.adapter.email.mode,
                crate::config::EmailMode::Bidirectional
            )
        {
            for (account, is_done) in &filtered_accounts {
                if let Account::Email(_) = account {
                    if !is_done {
                        if let Some(challenge) = verification.challenges.get_mut(&AccountType::Email)
                        {
                            if challenge.outbound_token == Some("pending".to_string()) {
                                challenge.outbound_token = Some(Token::generate().await.show());
                            }
                        }
                    }
                }
            }
        }

        conn.init_verification_state(network, who, &verification, &filtered_accounts)
            .await?;

        if matches!(cfg.adapter.email.protocol, crate::config::EmailProtocol::Jmap)
            && matches!(
                cfg.adapter.email.mode,
                crate::config::EmailMode::Send | crate::config::EmailMode::Bidirectional
            )
        {
            for (account, is_done) in &filtered_accounts {
                if let Account::Email(email_address) = account {
                    if !is_done {
                        if let Some(challenge) = verification.challenges.get(&AccountType::Email) {
                            let email_token = challenge
                                .outbound_token
                                .as_ref()
                                .or(challenge.token.as_ref());

                            if let Some(token) = email_token {
                                info!(
                                    "sending email challenge to {} for {}/{} with token: {}",
                                    email_address, network, who, token
                                );
                                if let Err(e) =
                                    send_email_challenge(email_address, token, network, who).await
                                {
                                    error!(
                                        "failed to send email challenge to {}: {}",
                                        email_address, e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let pg_conn = PostgresConnection::default().await?;
        pg_conn.init_timeline(who, network).await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn listen(self) -> anyhow::Result<()> {
        info!("starting node listener");

        let cfg = Config::load_static();
        let networks = cfg.registrar.supported_networks();

        let mut handles = Vec::new();

        for network in networks {
            let client = self
                .clients
                .get(&network)
                .ok_or_else(|| anyhow!("no client for network {}", network))?;

            let mut block_stream = client.blocks().subscribe_finalized().await?;
            let network_name = network.clone();
            let mut self_clone = self.clone();

            let handle = tokio::spawn(async move {
                while let Some(item) = block_stream.next().await {
                    match item {
                        Ok(block) => {
                            if let Ok(events) = block.events().await {
                                self_clone
                                    .process_block_events(events, &block, &network_name)
                                    .await;
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to process block")
                        }
                    }
                }
            });

            handles.push(handle);
        }

        futures::future::join_all(handles).await;
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn process_block_events(
        &mut self,
        events: subxt::events::Events<subxt::SubstrateConfig>,
        block: &Block,
        network: &Network,
    ) {
        let block_number = block.number();
        let block_hash = hex::encode(block.hash().0);

        // Use shared event processor to extract and store all identity events
        let processed_events = process_identity_events(&events, network, block_number, &block_hash).await;

        // Handle real-time actions for specific events
        for processed in &processed_events {
            // Handle JudgementRequested - trigger registration flow
            if let Some((who, registrar_index)) = is_judgement_requested(processed) {
                if let Err(e) = self
                    .handle_registration(&who, registrar_index, network)
                    .await
                {
                    error!(error = %e, requester = %who, "failed to process registration request");
                }
            }

            // Handle JudgementUnrequested - cancel registration
            if let Some((who, registrar_index)) = is_judgement_unrequested(processed) {
                if let Err(e) = self
                    .cancel_registration(&who, registrar_index, network)
                    .await
                {
                    error!(error = %e, requester = %who, "failed to cancel registration");
                }
            }

            // Handle JudgementGiven - save registration record
            if let Some((who, _registrar_index)) = is_judgement_given(processed) {
                if let Ok(Some(judgement)) = node::get_judgement(&who, network).await {
                    if matches!(judgement, Judgement::Reasonable | Judgement::KnownGood) {
                        if let Some(client) = self.clients.get(network) {
                            // Get the original event to extract JudgementGiven details
                            for event_result in events.iter() {
                                if let Ok(event) = event_result {
                                    if let Ok(Some(jud)) = event.as_event::<crate::node::identity::events::JudgementGiven>() {
                                        if jud.target == who {
                                            if let Ok(Some(record)) =
                                                RegistrationRecord::from_judgement(&jud, network, client).await
                                            {
                                                if let Err(e) = self
                                                    .save_registration_and_update_state(
                                                        &record,
                                                        network,
                                                        block_number,
                                                        &block.hash(),
                                                    )
                                                    .await
                                                {
                                                    error!(error = %e, "failed to save registration");
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn save_registration_and_update_state(
        &self,
        record: &RegistrationRecord,
        network: &Network,
        block_number: u32,
        block_hash: &sp_core::H256,
    ) -> anyhow::Result<()> {
        let mut conn = PostgresConnection::default().await?;
        info!(who = ?record.wallet_id(), registrar = ?record.judgement_by, "saving judgement to db");
        conn.save_registration(record).await?;
        conn.update_indexer_state(network, block_hash, &(block_number as i64))
            .await?;
        Ok(())
    }

    pub async fn handle_registration_request(
        conn: &mut RedisConnection,
        network: &Network,
        who: &AccountId32,
        accounts: &[(Account, bool)],
    ) -> anyhow::Result<()> {
        let mut verification = AccountVerification::new(network.to_string());

        for (account, is_done) in accounts {
            let (name, acc_type) = (account.inner(), account.account_type());

            let token = if account.should_skip_token(*is_done) {
                None
            } else {
                Some(Token::generate().await.show())
            };
            verification.add_challenge(&acc_type, name, token);
        }

        let accounts_map: HashMap<Account, bool> = accounts.iter().cloned().collect();

        conn.init_verification_state(network, who, &verification, &accounts_map)
            .await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn cancel_registration(
        &self,
        who: &AccountId32,
        index: u32,
        network: &Network,
    ) -> anyhow::Result<()> {
        let cfg = Config::load_static();

        let network_cfg = cfg.registrar.require_network(network)?;

        // Skip cancellation handling for inactive registrars (index-only mode)
        if !network_cfg.active {
            return Ok(());
        }

        if network_cfg.registrar_index != index {
            return Err(anyhow!(
                "invalid registrar index on network {network}, expected {} but got {index}",
                network_cfg.registrar_index
            ));
        }

        let mut conn = RedisConnection::get_connection().await?;
        conn.clear_all_related_to(network, who).await?;

        let pg_conn = PostgresConnection::default().await?;
        pg_conn.delete_timelines(who, network).await?;

        Ok(())
    }
}

#[instrument(name = "node_listener")]
pub async fn spawn_node_listener() -> anyhow::Result<()> {
    NodeListener::new().await?.listen().await
}
