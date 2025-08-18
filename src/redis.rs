use anyhow::anyhow;
use futures::{Stream, StreamExt};
use mobc::Connection;
use mobc::{async_trait, Manager, Pool};
use once_cell::sync::OnceCell;
use redis::aio::ConnectionManager;
use redis::aio::PubSub;
use redis::RedisResult;
use redis::{AsyncCommands, Msg};
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use subxt::utils::AccountId32;
use tracing::info;
use tracing::instrument;
use tracing::Span;

use crate::api::{Account, AccountVerification, VerificationFields};
use crate::api::{AccountType, Network};
use crate::config::RedisConfig;

static REDIS_CLIENT: OnceCell<Arc<Pool<RedisManager>>> = OnceCell::new();

pub struct RedisConnection {
    pub span: Span,
    pub manager: Connection<RedisManager>,
}

impl RedisConnection {
    #[instrument(skip_all, parent = None)]
    pub async fn default() -> anyhow::Result<Self> {
        Self::get_connection().await
    }

    /// Clears all caches
    #[instrument(skip_all, parent = &self.span)]
    pub async fn flushall(&mut self) -> anyhow::Result<()> {
        redis::cmd("FLUSHALL")
            .arg("ASYNC")
            .exec_async(&mut self.manager.0)
            .await?;
        Ok(())
    }

    // TODO: replace all occurance of .get_connection() to .default()
    #[instrument(skip_all, parent = None)]
    pub async fn initialize_pool(cfg: &RedisConfig) -> anyhow::Result<()> {
        info!("Initializing Redis client");

        let pool = Pool::builder()
            .max_open(cfg.max_open_clients)
            .build(RedisManager { addr: cfg.url()? });

        REDIS_CLIENT
            .set(Arc::new(pool))
            .map_err(|_| anyhow!("Redis client already initialized"))?;

        info!("Redis client initialized successfully");
        Ok(())
    }

    #[instrument(skip_all, name = "redis_connection", parent = None)]
    pub async fn get_connection() -> anyhow::Result<Self> {
        let span = tracing::Span::current();
        info!("Getting redis connection");
        let client = REDIS_CLIENT
            .get()
            .ok_or_else(|| anyhow!("Redis client not initialized"))?;

        let mut manager = client.get().await?;

        Self::enable_keyspace_notifications(&mut manager.0).await?;
        // Self::enable_keyspace_notifications(&mut manager.0).await?;
        // let pubsub = client.get_async_pubsub().await?;

        info!("Redis connection successfully established");
        Ok(Self { manager, span })
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn subscribe(&mut self, channel: &str) -> RedisResult<()> {
        info!(channel = %channel, "Subscribing to pubsub channel");
        self.manager.1.psubscribe(channel).await
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn pubsub_stream(&mut self) -> impl Stream<Item = Msg> + '_ {
        info!("Getting PubSub stream");
        self.manager.1.on_message()
    }

    #[instrument(skip_all, name = "keyspace_notification", parent = None)]
    async fn enable_keyspace_notifications(conn: &mut ConnectionManager) -> anyhow::Result<()> {
        info!("Enabling keyspace notification");

        match conn
            .send_packed_command(
                redis::cmd("CONFIG")
                    .arg("SET")
                    .arg("notify-keyspace-events")
                    .arg("KEA"),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow!("Cannot set notify-keyspace-events: {}", e)),
        }
    }

    /// Search through the redis for keys that are similar to the `pattern`
    #[instrument(skip_all, parent = &self.span)]
    pub async fn search(&mut self, pattern: &str) -> anyhow::Result<Vec<String>> {
        info!(pattern, "Searching");
        Ok(self
            .manager
            .0
            .scan_match::<&str, String>(pattern)
            .await?
            .collect::<Vec<String>>()
            .await)
    }

    /// Get all pending challenges of `wallet_id` as a [Vec<Vec<String>>]
    /// Returns pairs of [account_type, challenge_token]
    #[instrument(skip_all, parent = &self.span)]
    async fn get_challenges(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Vec<Vec<(AccountType, String)>>> {
        info!(account_id = ?account_id.to_string(), network = ?network, "Getting challenges");
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        info!(account_id = ?account_id.to_string(), network = ?network, "Filtering pending challenges");
        let pending = state
            .challenges
            .iter()
            .filter(|(_, challenge)| !challenge.done)
            .filter_map(|(acc_type, challenge)| {
                challenge
                    .token
                    .as_ref()
                    .map(|token| vec![(acc_type.clone(), token.clone())])
            })
            .collect();

        Ok(pending)
    }

    /// constructing [VerificationFields] object from the registration done of all the accounts
    /// under `wallet_id`
    #[instrument(skip_all, parent = &self.span)]
    pub async fn extract_info(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<VerificationFields> {
        info!(
            account_id = ?account_id.to_string(), network = ?network,
            "Extracting verification fields",
        );
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(VerificationFields::default()),
        };

        let mut fields = VerificationFields::default();

        for (acc_type, challenge) in &state.challenges {
            if challenge.done {
                match acc_type {
                    AccountType::Discord => fields.discord = true,
                    AccountType::Display => fields.display_name = true,
                    AccountType::Email => fields.email = true,
                    AccountType::Matrix => fields.matrix = true,
                    AccountType::Twitter => fields.twitter = true,
                    AccountType::Github => fields.github = true,
                    AccountType::Legal => fields.legal = true,
                    AccountType::Web => fields.web = true,
                    AccountType::PGPFingerprint => fields.pgp_fingerprint = true,
                }
            }
        }

        Ok(fields)
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn clear_all_related_to(
        &mut self,
        network: &Network,
        who: &AccountId32,
    ) -> anyhow::Result<()> {
        let mut pipe = redis::pipe();
        pipe.cmd("DEL").arg(format!("{who}|{network}"));

        let accounts = self.search(&format!("*|{network}|{who}")).await?;
        for account in accounts {
            pipe.cmd("DEL").arg(account);
        }

        pipe.exec_async(&mut self.manager.0).await?;
        Ok(())
    }

    pub async fn save_account(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        info!(state = ?state, "Saving account state");
        let mut pipe = redis::pipe();
        for account in accounts.keys() {
            let key = format!("{account}|{network}|{account_id}");
            let pipe = pipe.cmd("SET").arg(&key);
            if let Some(challenge_info) = state.challenges.get(&account.account_type()) {
                pipe.arg(&serde_json::to_string(&challenge_info)?);
            }
        }
        pipe.exec_async(&mut self.manager.0).await?;
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn save_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        let key = format!("{account_id}|{network}");
        info!(state = ?state, "Saving account state");
        let value = serde_json::to_string(&state)?;

        redis::pipe()
            .cmd("SET")
            .arg(&key)
            .arg(value)
            .exec_async(&mut self.manager.0)
            .await?;

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn update_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        self.save_state(network, account_id, state).await?;
        let mut pipe = redis::pipe();

        for (acc_type, info) in state.challenges.iter() {
            let acc_key = Account::from_type_and_value(acc_type.to_owned(), info.name.to_string());
            let key = format!("{acc_key}|{network}|{account_id}");
            pipe.cmd("SET")
                .arg(&key)
                .arg(&serde_json::to_string(&info)?);
        }

        pipe.exec_async(&mut self.manager.0).await?;
        Ok(())
    }

    // #[instrument(skip_all, parent = &self.span)]
    // NOTE: don't instrument this
    #[instrument(skip_all, parent = &self.span)]
    pub async fn init_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        self.save_state(network, account_id, state).await?;
        self.save_account(network, account_id, state, accounts)
            .await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span, name = "verification_state")]
    pub async fn get_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Option<AccountVerification>> {
        let key = format!("{account_id}|{network}");
        info!(account_id = ?account_id.to_string(), network = ?network, "Getting verification state");
        let value: Option<String> = self.manager.0.get(&key).await?;

        match value {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn update_challenge_status(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        account_type: &AccountType,
    ) -> anyhow::Result<bool> {
        info!(
            network = ?network,
            account_id = ?account_id.to_string(),
            account_type = ?account_type,
            "Updating challenge state"
        );
        if let Some(mut state) = self.get_verification_state(network, account_id).await? {
            state.mark_challenge_done(account_type)?;
            self.update_verification_state(network, account_id, &state)
                .await?;
            return Ok(true);
        }
        return Ok(false);
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn build_account_state_message(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        hash: Option<String>, // optional for state updates
    ) -> anyhow::Result<serde_json::Value> {
        let fields = self.extract_info(network, account_id).await?;
        let pending_challenges = self.get_challenges(network, account_id).await?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": {
                    "AccountState": {
                        "account": account_id.to_string(),
                        "network": network,
                        "hashed_info": hash,
                        "verification_state": {
                            "fields": fields
                        },
                        "pending_challenges": pending_challenges
                    }
                }
            }
        }))
    }

    #[instrument(skip_all)]
    pub async fn process_state_change(
        msg: &redis::Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection().await?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(payload = ?payload, channel = ?channel, "Processing Redis message");

        // early returns for unsupported operations
        if !matches!(payload.as_str(), "set" | "del") {
            info!(payload = ?payload, "Ignoring Redis operation");
            return Ok(None);
        }

        // extract key from channel name
        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => return Ok(None),
        };

        // parse network and account ID
        let (account_id, network) = match key.split_once('|') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let network = Network::from_str(network)?;

        let id = match AccountId32::from_str(account_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        let account_state = conn
            .build_account_state_message(&network, &id, None)
            .await?;

        Ok(Some((id, account_state)))
    }

    /// Check if a key exist in redis db
    /// Wrapper for the [redis::commands::AsyncCommands::exists]
    pub async fn exists(&mut self, key: &str) -> anyhow::Result<bool> {
        self.manager
            .0
            .exists(key)
            .await
            .map_err(|e| anyhow!("Failed to check state in Redis: {}", e))
    }

    /// Set the value and expiration of a key.
    /// Wrapper around [redis::commands::AsyncCommands::set_ex]
    pub async fn set_ex(&mut self, key: &str, value: &str, seconds: u64) -> anyhow::Result<()> {
        self.manager
            .0
            .set_ex(key, value, seconds)
            .await
            .map_err(|e| {
                anyhow!(
                    "Failed to set expiration date for key={} value={} seconds={} in Redis: {}",
                    key,
                    value,
                    seconds,
                    e
                )
            })
    }

    /// Delete one or more keys.
    /// Wrapper around [redis::commands::AsyncCommands::del]
    pub async fn del(&mut self, key: &str) -> anyhow::Result<()> {
        self.manager
            .0
            .del(&key)
            .await
            .map_err(|e| anyhow!("Failed to remove state from Redis: {}", e))
    }
}

pub struct RedisManager {
    addr: url::Url,
}

#[async_trait]
impl Manager for RedisManager {
    type Connection = (ConnectionManager, PubSub);
    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let client = redis::Client::open(self.addr.clone()).unwrap();
        let pubsub = client.get_async_pubsub().await.unwrap();
        let manager = ConnectionManager::new(client).await.unwrap();
        Ok((manager, pubsub))
    }

    async fn check(&self, mut conn: Self::Connection) -> Result<Self::Connection, Self::Error> {
        let res: Result<(), _> = conn.0.ping().await;
        match res {
            Ok(_) => return Ok(conn),
            Err(_) => return Err(anyhow!("Connnection ended")),
        }
    }
}
