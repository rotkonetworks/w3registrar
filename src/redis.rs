use anyhow::anyhow;
use futures::{Stream, StreamExt};
use async_trait::async_trait;
use bb8::{Pool, PooledConnection, ManageConnection};
use redis::aio::MultiplexedConnection;
use redis::aio::PubSub;
use redis::{AsyncCommands, Msg, RedisResult};
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use subxt::utils::AccountId32;
use tokio::sync::OnceCell;
use tracing::{info, instrument, Span};

use crate::api::{Account, AccountVerification, VerificationFields};
use crate::api::{AccountType, Network};
use crate::config::RedisConfig;

/// Global Redis pool - initialized once at startup
static REDIS_POOL: OnceCell<Arc<RedisPool>> = OnceCell::const_new();

/// Redis pool wrapper that separates connection pooling from PubSub
pub struct RedisPool {
    pool: Pool<RedisConnectionManager>,
    url: url::Url,
}

impl RedisPool {
    /// Initialize the global Redis pool
    pub async fn initialize(cfg: &RedisConfig) -> anyhow::Result<()> {
        let url = cfg.url()?;
        info!("Initializing Redis pool");

        let manager = RedisConnectionManager::new(url.clone())?;
        let pool = Pool::builder()
            .max_size(cfg.max_open_clients as u32)
            .min_idle(Some(2))
            .build(manager)
            .await?;

        // Enable keyspace notifications once at startup
        {
            let mut conn = pool.get().await
                .map_err(|e| anyhow!("Failed to get initial Redis connection: {}", e))?;
            Self::enable_keyspace_notifications(&mut conn).await?;
        }

        let redis_pool = Arc::new(RedisPool { pool, url });

        REDIS_POOL
            .set(redis_pool)
            .map_err(|_| anyhow!("Redis pool already initialized"))?;

        info!("Redis pool initialized successfully");
        Ok(())
    }

    /// Get the global pool instance
    pub fn get() -> anyhow::Result<Arc<RedisPool>> {
        REDIS_POOL
            .get()
            .cloned()
            .ok_or_else(|| anyhow!("Redis pool not initialized"))
    }

    /// Get a connection from the pool
    pub async fn connection(&self) -> anyhow::Result<PooledConnection<'_, RedisConnectionManager>> {
        self.pool
            .get()
            .await
            .map_err(|e| anyhow!("Failed to get Redis connection: {}", e))
    }

    /// Create a new PubSub connection (not pooled - each subscriber needs its own)
    pub async fn pubsub(&self) -> anyhow::Result<PubSub> {
        let client = redis::Client::open(self.url.clone())?;
        let pubsub = client.get_async_pubsub().await?;
        Ok(pubsub)
    }

    /// Enable keyspace notifications on a connection
    async fn enable_keyspace_notifications(conn: &mut MultiplexedConnection) -> anyhow::Result<()> {
        info!("Enabling keyspace notifications");
        conn.send_packed_command(
            redis::cmd("CONFIG")
                .arg("SET")
                .arg("notify-keyspace-events")
                .arg("KEA"),
        )
        .await
        .map_err(|e| anyhow!("Cannot set notify-keyspace-events: {}", e))?;
        Ok(())
    }
}

/// bb8 connection manager for Redis
pub struct RedisConnectionManager {
    client: redis::Client,
}

impl RedisConnectionManager {
    pub fn new(url: url::Url) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ManageConnection for RedisConnectionManager {
    type Connection = MultiplexedConnection;
    type Error = redis::RedisError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        self.client.get_multiplexed_async_connection().await
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        redis::cmd("PING").query_async(conn).await
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

/// High-level Redis operations wrapper
pub struct RedisConnection {
    pub span: Span,
    conn: MultiplexedConnection,
}

impl RedisConnection {
    #[instrument(skip_all, parent = None)]
    pub async fn default() -> anyhow::Result<Self> {
        Self::get_connection().await
    }

    #[instrument(skip_all, parent = None)]
    pub async fn initialize_pool(cfg: &RedisConfig) -> anyhow::Result<()> {
        RedisPool::initialize(cfg).await
    }

    #[instrument(skip_all, name = "redis_connection", parent = None)]
    pub async fn get_connection() -> anyhow::Result<Self> {
        let span = tracing::Span::current();

        let pool = RedisPool::get()?;
        let conn = pool.connection().await?;

        // Clone the connection for our wrapper (MultiplexedConnection is cheap to clone)
        Ok(Self {
            conn: conn.clone(),
            span,
        })
    }

    /// Create a new PubSub subscriber
    #[instrument(skip_all, name = "redis_pubsub", parent = None)]
    pub async fn new_pubsub() -> anyhow::Result<RedisPubSub> {
        let pool = RedisPool::get()?;
        let pubsub = pool.pubsub().await?;
        Ok(RedisPubSub { pubsub })
    }

    /// Search through redis for keys matching pattern
    #[instrument(skip_all, parent = &self.span)]
    pub async fn search(&mut self, pattern: &str) -> anyhow::Result<Vec<String>> {
        info!(pattern, "Searching");
        Ok(self
            .conn
            .scan_match::<&str, String>(pattern)
            .await?
            .collect::<Vec<String>>()
            .await)
    }

    /// Get all pending challenges for an account
    #[instrument(skip_all, parent = &self.span)]
    async fn get_challenges(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Vec<Challenge>> {
        use crate::config::{EmailProtocol, EmailMode, GLOBAL_CONFIG};
        use crate::api::AccountType;

        info!(account_id = ?account_id.to_string(), network = ?network, "Getting challenges");
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let is_automated_email = if let Some(cfg) = GLOBAL_CONFIG.get() {
            matches!(cfg.adapter.email.protocol, EmailProtocol::Jmap)
                && matches!(cfg.adapter.email.mode, EmailMode::Send | EmailMode::Bidirectional)
        } else {
            false
        };

        info!(account_id = ?account_id.to_string(), network = ?network, automated_email = ?is_automated_email, "Filtering pending challenges");
        let pending = state
            .challenges
            .iter()
            .filter(|(_, challenge)| !challenge.done)
            .filter_map(|(acc_type, challenge)| {
                if matches!(acc_type, AccountType::Email) && is_automated_email {
                    let cfg = GLOBAL_CONFIG.get().expect("Config not initialized");
                    let display = match &cfg.adapter.email.mode {
                        EmailMode::Bidirectional => challenge.inbound_token.as_ref()
                            .cloned()
                            .unwrap_or_else(|| "pending".to_string()),
                        EmailMode::Send => "✉️ Check your email".to_string(),
                        _ => challenge.inbound_token.as_ref()
                            .or(challenge.token.as_ref())
                            .cloned()
                            .unwrap_or_else(|| "pending".to_string()),
                    };
                    Some(Challenge::new(acc_type.to_owned(), challenge.account_name.to_owned(), display))
                } else {
                    let token = match acc_type {
                        AccountType::Email => challenge.inbound_token.as_ref().or(challenge.token.as_ref()),
                        _ => challenge.token.as_ref(),
                    }?;
                    Some(Challenge::new(acc_type.to_owned(), challenge.account_name.to_owned(), token.to_owned()))
                }
            })
            .collect();

        Ok(pending)
    }

    /// Extract verification fields from account state
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
                    AccountType::Image => fields.image = true,
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

    /// Clear all Redis keys related to an account (atomic)
    #[instrument(skip_all, parent = &self.span)]
    pub async fn clear_all_related_to(
        &mut self,
        network: &Network,
        who: &AccountId32,
    ) -> anyhow::Result<()> {
        let accounts = self.search(&format!("*|{network}|{who}")).await?;

        // Use atomic transaction
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("DEL").arg(format!("{who}|{network}"));

        for account in accounts {
            pipe.cmd("DEL").arg(account);
        }

        pipe.exec_async(&mut self.conn).await?;
        Ok(())
    }

    /// Save account state (atomic)
    pub async fn save_account(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        info!(state = ?state, "Saving account state");

        let mut pipe = redis::pipe();
        pipe.atomic();

        for account in accounts.keys() {
            let key = format!("{account}|{network}|{account_id}");
            if let Some(challenge_info) = state.challenges.get(&account.account_type()) {
                pipe.cmd("SET")
                    .arg(&key)
                    .arg(&serde_json::to_string(&challenge_info)?);
            }
        }

        pipe.exec_async(&mut self.conn).await?;
        Ok(())
    }

    /// Save verification state (atomic)
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

        let _: () = self.conn.set(&key, value).await?;
        Ok(())
    }

    /// Update verification state with all related keys (atomic transaction)
    #[instrument(skip_all)]
    pub async fn update_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        const TTL_SECONDS: i64 = 7 * 24 * 3600; // 7 days

        let main_key = format!("{account_id}|{network}");
        let main_value = serde_json::to_string(&state)?;

        // Use atomic transaction for all updates
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&main_key).arg(&main_value)
            .cmd("EXPIRE").arg(&main_key).arg(TTL_SECONDS);

        for (acc_type, info) in state.challenges.iter() {
            let acc_key =
                Account::from_type_and_value(acc_type.to_owned(), info.account_name.to_string());
            let key = format!("{acc_key}|{network}|{account_id}");
            pipe.cmd("SET")
                .arg(&key)
                .arg(&serde_json::to_string(&info)?)
                .cmd("EXPIRE").arg(&key).arg(TTL_SECONDS);
        }

        pipe.exec_async(&mut self.conn).await?;
        Ok(())
    }

    /// Initialize verification state (atomic)
    /// Keys expire after 7 days to prevent unbounded growth from abandoned requests
    #[instrument(skip_all, parent = &self.span)]
    pub async fn init_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        const TTL_SECONDS: i64 = 7 * 24 * 3600; // 7 days

        let main_key = format!("{account_id}|{network}");
        let main_value = serde_json::to_string(&state)?;

        // Use atomic transaction
        let mut pipe = redis::pipe();
        pipe.atomic();
        pipe.cmd("SET").arg(&main_key).arg(&main_value)
            .cmd("EXPIRE").arg(&main_key).arg(TTL_SECONDS);

        for account in accounts.keys() {
            let key = format!("{account}|{network}|{account_id}");
            if let Some(challenge_info) = state.challenges.get(&account.account_type()) {
                pipe.cmd("SET")
                    .arg(&key)
                    .arg(&serde_json::to_string(&challenge_info)?)
                    .cmd("EXPIRE").arg(&key).arg(TTL_SECONDS);
            }
        }

        info!(state = ?state, "Saving account state");
        pipe.exec_async(&mut self.conn).await?;
        Ok(())
    }

    /// Get verification state for an account
    #[instrument(skip_all, parent = &self.span, name = "verification_state")]
    pub async fn get_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Option<AccountVerification>> {
        let key = format!("{account_id}|{network}");
        info!(account_id = ?account_id.to_string(), network = ?network, "Getting verification state");
        let value: Option<String> = self.conn.get(&key).await?;

        match value {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Update challenge status (idempotent)
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
            // Check if already done (idempotent)
            if let Some(challenge) = state.challenges.get(account_type) {
                if challenge.done {
                    info!(account_type = ?account_type, "Challenge already marked done");
                    return Ok(true);
                }
            }

            state.mark_challenge_done(account_type)?;
            self.update_verification_state(network, account_id, &state).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Clear verification state for an account
    #[instrument(skip_all, parent = &self.span)]
    pub async fn clear_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<()> {
        let key = format!("{account_id}|{network}");
        info!(account_id = ?account_id.to_string(), network = ?network, "Clearing verification state");
        let _: () = self.conn.del(&key).await?;
        Ok(())
    }

    /// Build account state message for WebSocket response
    #[instrument(skip_all, parent = &self.span)]
    pub async fn build_account_state_message(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        hash: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        let fields = self.extract_info(network, account_id).await?;
        let pending_challenges = self.get_challenges(network, account_id).await?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": {
                    "AccountState": {
                        "account": network.format_account(account_id),
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

    /// Process a Redis keyspace change notification
    #[instrument(skip_all)]
    pub async fn process_state_change(
        msg: &redis::Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection().await?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(payload = ?payload, channel = ?channel, "Processing Redis message");

        if !matches!(payload.as_str(), "set" | "del") {
            info!(payload = ?payload, "Ignoring Redis operation");
            return Ok(None);
        }

        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => return Ok(None),
        };

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

    /// Check if a key exists
    pub async fn exists(&mut self, key: &str) -> anyhow::Result<bool> {
        self.conn
            .exists(key)
            .await
            .map_err(|e| anyhow!("Failed to check state in Redis: {}", e))
    }

    /// Set key with expiration
    pub async fn set_ex(&mut self, key: &str, value: &str, seconds: u64) -> anyhow::Result<()> {
        self.conn
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

    /// Delete a key
    pub async fn del(&mut self, key: &str) -> anyhow::Result<()> {
        self.conn
            .del(key)
            .await
            .map_err(|e| anyhow!("Failed to remove state from Redis: {}", e))
    }
}

/// Separate PubSub wrapper for subscription handling
pub struct RedisPubSub {
    pubsub: PubSub,
}

impl RedisPubSub {
    /// Subscribe to a pattern
    pub async fn psubscribe(&mut self, pattern: &str) -> RedisResult<()> {
        info!(pattern = %pattern, "Subscribing to pubsub pattern");
        self.pubsub.psubscribe(pattern).await
    }

    /// Subscribe to a channel
    pub async fn subscribe(&mut self, channel: &str) -> RedisResult<()> {
        info!(channel = %channel, "Subscribing to pubsub channel");
        self.pubsub.subscribe(channel).await
    }

    /// Get the message stream
    pub fn on_message(&mut self) -> impl Stream<Item = Msg> + '_ {
        self.pubsub.on_message()
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Challenge {
    account_type: AccountType,
    account_name: String,
    challenge: String,
}

impl Challenge {
    fn new(account_type: AccountType, account_name: String, challenge: String) -> Self {
        Self {
            account_type,
            account_name,
            challenge,
        }
    }
}

// Implement VerificationStore trait for RedisConnection
#[async_trait]
impl crate::adapter::context::VerificationStore for RedisConnection {
    async fn get_verification_state(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
    ) -> anyhow::Result<Option<AccountVerification>> {
        self.get_verification_state(network, account_id).await
    }

    async fn update_challenge_status(
        &mut self,
        network: &Network,
        account_id: &AccountId32,
        account_type: &AccountType,
    ) -> anyhow::Result<()> {
        self.update_challenge_status(network, account_id, account_type).await?;
        Ok(())
    }
}

