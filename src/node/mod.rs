#![allow(dead_code)]

#[subxt::subxt(runtime_metadata_path = "./identity.scale")]
pub mod substrate {}

use crate::api::AccountType;
use crate::api::AccountVerification;
use crate::common::*;
use crate::config::RedisConfig;
use crate::config::GLOBAL_CONFIG;
use crate::redis::RedisConnection;
use crate::token::AuthToken;
use crate::token::Token;

use anyhow::{anyhow, Result};
use identity::events::{JudgementRequested, JudgementUnrequested};
use sp_core::blake2_256;
use sp_core::Encode;
use std::collections::HashMap;
use std::str::FromStr;
use subxt::events::EventDetails;
use subxt::ext::sp_core::sr25519::Pair as Sr25519Pair;
use subxt::ext::sp_core::Pair;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tracing::{error, info, span, Level};

use super::api::Account;
use substrate::identity::calls::types::provide_judgement::Identity;
use substrate::runtime_types::pallet_identity::types::Judgement;
use substrate::runtime_types::pallet_identity::types::Registration;
use substrate::runtime_types::people_rococo_runtime::people::IdentityInfo;

pub use substrate::*;
pub type Client = subxt::OnlineClient<SubstrateConfig>;
pub type Block = subxt::blocks::Block<SubstrateConfig, Client>;
pub type BlockHash = <SubstrateConfig as subxt::Config>::Hash;
type PairSigner = subxt::tx::PairSigner<SubstrateConfig, Sr25519Pair>;

pub async fn get_registration(
    client: &Client,
    who: &AccountId32,
) -> Result<Registration<u128, IdentityInfo>> {
    let storage = client.storage().at_latest().await?;
    let identity = super::node::storage().identity().identity_of(who);
    info!("identity: {:?}", identity);
    match storage.fetch(&identity).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}

pub async fn provide_judgement<'a>(
    who: &AccountId32,
    reg_index: u32,
    judgement: Judgement<u128>,
    endpoint: &str,
) -> anyhow::Result<&'a str> {
    let client = Client::from_url(endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} because of {}",
            endpoint,
            e.to_string()
        )
    })?;
    let registration = get_registration(&client, &who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    let judgement = substrate::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        judgement,
        Identity::from_str(&hash)?,
    );

    let signer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        // TODO: config the "//Alice" part?
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//FERDIE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &signer, conf).await {
        Ok(_) => return Ok("Judged with reasonable"),
        Err(_) => return Err(anyhow!("unable to submit judgement")),
    }
}

/// Filters all requested accounts to include only those that we can handle, and default
/// the judgement of other accounts to `Erroneous`, and the judgement for empty identity
/// objects to `Unknown`
pub async fn filter_accounts(
    info: &IdentityInfo,
    who: &AccountId32,
    reg_index: u32,
    network: &str,
) -> anyhow::Result<HashMap<Account, bool>> {
    let accounts = Account::into_accounts(info);

    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    // supported fields from cfg
    let supported = &network_cfg.fields;

    if accounts.is_empty() {
        provide_judgement(who, reg_index, Judgement::Unknown, &network_cfg.endpoint).await?;
        return Ok(HashMap::new());
    }

    for account in &accounts {
        let account_type = account.account_type();
        if !supported
            .iter()
            .any(|s| AccountType::from_str(s).ok() == Some(account_type))
        {
            provide_judgement(who, reg_index, Judgement::Erroneous, &network_cfg.endpoint).await?;
            return Ok(HashMap::new());
        }
    }

    Ok(Account::into_hashmap(accounts, false))
}

/// This will provide a [Reasonable] judgement for the account id `who` from the registrar with
/// index `regi_index`
// TODO: Takea RegistrarConfig instead?
pub async fn register_identity<'a>(
    who: &AccountId32,
    reg_index: u32,
    network: &str,
) -> anyhow::Result<&'a str> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");

    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    let client = Client::from_url(&network_cfg.endpoint).await.map_err(|e| {
        anyhow!(
            "unable to connect to {} network({}) because of {}",
            network,
            network_cfg.endpoint,
            e.to_string(),
        )
    })?;

    let registration = get_registration(&client, who).await?;
    let hash = hex::encode(blake2_256(&registration.info.encode()));

    let judgement = substrate::tx().identity().provide_judgement(
        reg_index,
        subxt::utils::MultiAddress::Address32(who.to_owned().0),
        Judgement::Reasonable,
        Identity::from_str(&hash)?,
    );

    // TODO: use from keyfile + add IdentityJudgement proxy
    let signer: subxt::tx::signer::PairSigner<SubstrateConfig, subxt::ext::sp_core::sr25519::Pair> = {
        let acc = subxt::ext::sp_core::sr25519::Pair::from_string("//ALICE", None)?;
        subxt::tx::PairSigner::new(acc)
    };

    let conf = subxt::config::substrate::SubstrateExtrinsicParamsBuilder::new().build();
    match client.tx().sign_and_submit(&judgement, &signer, conf).await {
        Ok(_) => Ok("Judged with reasonable"),
        Err(e) => Err(anyhow!("unable to submit judgement\nError: {:?}", e)),
    }
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
pub struct NodeListener {
    clients: HashMap<String, Client>,
    redis_cfg: RedisConfig,
}

impl NodeListener {
    /// Creates a new [NodeListener]
    ///
    /// # Panics
    /// This function will fail if the _redis_url_ is an invalid url to a redis server
    /// or if _node_url_ is not a valid url for a substrate BC node
    pub async fn new() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let mut clients = HashMap::new();

        for (network, network_cfg) in &cfg.registrar.networks {
            let client = Client::from_url(&network_cfg.endpoint)
                .await
                .map_err(|e| anyhow!("Failed to connect to {} network: {}", network, e))?;
            clients.insert(network.clone(), client);
        }

        Ok(Self {
            clients,
            redis_cfg: cfg.redis.clone(),
        })
    }

    async fn handle_registration(
        &mut self,
        who: &AccountId32,
        network: &str,
    ) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        let client = self
            .clients
            .get(network)
            .ok_or_else(|| anyhow!("No client for network {}", network))?;

        let registration = get_registration(&client, who).await?;
        let accounts = Account::into_accounts(&registration.info);

        // ----------------------------------------------------------------------------
        // validation
        check_node(who.clone(), accounts.clone(), network).await?;

        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;
        conn.clear_all_related_to(network, who).await?;

        // filter accounts and create verification state
        let filtered_accounts = filter_accounts(
            &registration.info,
            who,
            network_cfg.registrar_index,
            network,
        )
        .await?;
        // ----------------------------------------------------------------------------

        let mut verification = AccountVerification::new(network.to_string());

        // set up verification challenges
        for (account, is_done) in &filtered_accounts {
            let (acc_type, name) = match account {
                Account::Discord(name) => ("discord", name.clone()),
                Account::Twitter(name) => ("twitter", name.clone()),
                Account::Matrix(name) => ("matrix", name.clone()),
                Account::Display(name) => ("display_name", name.clone()),
                Account::Email(name) => ("email", name.clone()),
                Account::Github(name) => ("github", name.clone()),
                Account::Legal(name) => ("legal", name.clone()),
                Account::Web(name) => ("web", name.clone()),
                Account::PGPFingerprint(bytes) => ("pgp_fingerprint", hex::encode(bytes)),
            };

            let token = if *is_done {
                None
            } else {
                Some(Token::generate().await.show())
            };

            verification.add_challenge(acc_type, name, token);
        }

        // Save verification state to Redis
        conn.init_verification_state(network, who, &verification, &filtered_accounts)
            .await?;

        Ok(())
    }

    pub async fn handle_node_events(
        &mut self,
        event: EventDetails<SubstrateConfig>,
        network: &str,
    ) {
        let span = span!(Level::INFO, "node_event", %network);

        if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
            info!(parent: &span, requester = %req.who, "Judgement requested");

            match self.handle_registration(&req.who, network).await {
                Ok(_) => {
                    info!(parent: &span, requester = %req.who, "Successfully processed registration request")
                }
                Err(e) => {
                    error!(parent: &span, error = %e, requester = %req.who, "Failed to process registration request")
                }
            }
        } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
            info!(parent: &span, requester = %req.who, "Judgement unrequested");

            match self.cancel_registration(&req.who, network).await {
                Ok(_) => {
                    info!(parent: &span, requester = %req.who, "Successfully cancelled registration")
                }
                Err(e) => {
                    error!(parent: &span, error = %e, requester = %req.who, "Failed to cancel registration")
                }
            }
        }
    }

    /// Listens for incoming events on the substrate node, in particular
    /// the `requestJudgement` event
    pub async fn listen(self) -> anyhow::Result<()> {
        let span = span!(Level::INFO, "node_listener");
        info!(parent: &span, "Starting node listener");

        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let networks = cfg.registrar.supported_networks();

        let mut handles = Vec::new();

        for network in networks {
            let client = self
                .clients
                .get(&network)
                .ok_or_else(|| anyhow!("No client for network {}", network))?;

            let mut block_stream = client.blocks().subscribe_finalized().await?;
            let network_name = network.clone();
            let mut self_clone = self.clone();
            let span_clone = span.clone();

            let handle = tokio::spawn(async move {
                while let Some(item) = block_stream.next().await {
                    match item {
                        Ok(block) => {
                            if let Ok(events) = block.events().await {
                                self_clone
                                    .process_block_events(&span_clone, events, &network_name)
                                    .await;
                            }
                        }
                        Err(e) => {
                            error!(parent: &span_clone, error = %e, "Failed to process block")
                        }
                    }
                }
            });

            handles.push(handle);
        }

        futures::future::join_all(handles).await;
        Ok(())
    }

    /// process block events we listen
    async fn process_block_events(
        &mut self,
        span: &tracing::Span,
        events: subxt::events::Events<SubstrateConfig>,
        network: &str,
    ) {
        for event_result in events.iter() {
            if let Ok(event) = event_result {
                if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
                    info!(parent: span, requester = %req.who, "Judgement requested");

                    match self.handle_registration(&req.who, network).await {
                        Ok(_) => {
                            info!(parent: span, requester = %req.who, "Successfully processed registration request")
                        }
                        Err(e) => {
                            error!(parent: span, error = %e, requester = %req.who, "Failed to process registration request")
                        }
                    }
                } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
                    info!(parent: span, requester = %req.who, "Judgement unrequested");

                    match self.cancel_registration(&req.who, network).await {
                        Ok(_) => {
                            info!(parent: span, requester = %req.who, "Successfully cancelled registration")
                        }
                        Err(e) => {
                            error!(parent: span, error = %e, requester = %req.who, "Failed to cancel registration")
                        }
                    }
                }
            }
        }
    }

    /// Handles incoming registration request via the `JudgementRequested` event by first checking
    /// if the requested fields/accounts can be verified, and if so, saves the registration request
    /// to `redis` as `done:false` otherwise, issue `Erroneous` judgement and save the registration
    /// request as `done:true`
    ///
    /// # Note
    /// For now, we only handle registration requests from `Matrix`, `Twitter` and `Discord`
    /// # TODO: remove this
    pub async fn handle_registration_request(
        conn: &mut RedisConnection,
        network: &str,
        who: &AccountId32,
        accounts: &[(Account, bool)],
    ) -> anyhow::Result<()> {
        let mut verification = AccountVerification::new(network.to_string());

        for (account, is_done) in accounts {
            let (acc_type, name) = match account {
                Account::Discord(name) => ("discord", name),
                Account::Twitter(name) => ("twitter", name),
                Account::Matrix(name) => ("matrix", name),
                Account::Display(name) => ("display_name", name),
                Account::Email(name) => ("email", name),
                Account::Github(name) => ("github", name),
                Account::Legal(name) => ("legal", name),
                Account::Web(name) => ("web", name),
                Account::PGPFingerprint(bytes) => ("pgp_fingerprint", &hex::encode(bytes)),
            };

            let token = if *is_done {
                None
            } else {
                Some(Token::generate().await.show())
            };

            verification.add_challenge(acc_type, name.clone(), token);
        }

        // convert accounts slice to HashMap
        let accounts_map: HashMap<Account, bool> = accounts.iter().cloned().collect();

        // save verification state to Redis
        conn.init_verification_state(network, who, &verification, &accounts_map)
            .await?;

        Ok(())
    }

    /// Cancels the pending registration requests issued by `who` by removing it's occurance on
    /// our `redis` server.
    ///
    /// # Note
    /// this method should be used in conjunction with the `JudgementUnrequested` event
    async fn cancel_registration(&self, who: &AccountId32, network: &str) -> anyhow::Result<()> {
        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;
        conn.clear_all_related_to(network, who).await?;
        Ok(())
    }
}

pub async fn spawn_node_listener() -> anyhow::Result<()> {
    let node_listener = NodeListener::new().await?;
    node_listener.listen().await
}
