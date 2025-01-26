use std::collections::HashMap;

use crate::api::AccountType;
use crate::api::{Account, AccountVerification, VerificationFields};
use crate::common::identity_data_tostring;
use crate::token::Token;
use anyhow::anyhow;
use redis::Commands;
use subxt::utils::AccountId32;
use std::str::FromStr;
use tracing::{error, info, span, Level};
use redis::Client as RedisClient;
use crate::config::RedisConfig;

pub async fn spawn_redis_subscriber(redis_cfg: RedisConfig) -> anyhow::Result<()> {
    let span = span!(Level::INFO, "redis_subscriber");
    info!(parent: &span, "Starting Redis subscriber service");

    let mut redis_conn = RedisConnection::create_conn(&redis_cfg)?;
    let mut pubsub = redis_conn.as_pubsub();

    while let Ok(msg) = pubsub.get_message() {
        if let Err(e) = handle_redis_message(&redis_cfg, &msg).await {
            error!(parent: &span, error = %e, "Failed to handle Redis message");
            continue;
        }
    }

    info!(parent: &span, "Redis subscription ended");
    Ok(())
}

async fn handle_redis_message(redis_cfg: &RedisConfig, msg: &redis::Msg) -> anyhow::Result<()> {
    if let Ok(Some((id, value))) = RedisConnection::process_state_change(redis_cfg, msg).await {
        info!("Processed state change for {}: {:?}", id, value);
    }
    Ok(())
}

pub struct RedisConnection {
    pub conn: redis::Connection,
}

impl RedisConnection {
    pub fn create_conn(addr: &RedisConfig) -> anyhow::Result<Self> {
        let span = span!(Level::INFO, "redis_connection", url = %addr.url()?);

        info!(parent: &span, "Attempting to establish Redis connection");

        let client = RedisClient::open(addr.url()?).map_err(|e| {
            error!(parent: &span, error = %e, "Failed to open Redis client");
            anyhow!("Cannot open Redis client: {}", e)
        })?;

        let mut conn = client.get_connection().map_err(|e| {
            error!(parent: &span, error = %e, "Failed to establish Redis connection");
            anyhow!("Cannot establish Redis connection: {}", e)
        })?;

        info!(parent: &span, "Enabling keyspace notifications");
        RedisConnection::enable_keyspace_notifications(&mut conn)?;

        info!(parent: &span, "Redis connection successfully established");
        Ok(Self { conn })
    }

    pub fn as_pubsub(&mut self) -> redis::PubSub<'_> {
        self.conn.as_pubsub()
    }

    fn enable_keyspace_notifications(conn: &mut redis::Connection) -> anyhow::Result<()> {
        redis::cmd("CONFIG")
            .arg("SET")
            .arg("notify-keyspace-events")
            .arg("KEA")
            .query::<()>(&mut *conn)
            .map_err(|e| anyhow!("Cannot set notify-keyspace-events: {}", e))
    }

    /// Subscribe to all relevant keys for the given account
    pub async fn subscribe_to_account_changes(
        &mut self,
        account_id: &AccountId32,
    ) -> anyhow::Result<redis::PubSub> {
        //        let related_keys = self.search(format!("*:{}", serde_json::to_string(&account_id)?))?;
        let related_keys = self.search(&format!("*:{}", account_id.to_string()))?;
        let mut pubsub = self.conn.as_pubsub();

        for key in related_keys {
            let channel = format!("__keyspace@0__:{}", key);
            pubsub.subscribe(&channel)?;
        }

        Ok(pubsub)
    }

    /// Search through the redis for keys that are similar to the `pattern`
    pub fn search(&mut self, pattern: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .conn
            .scan_match::<&str, String>(pattern)?
            .collect::<Vec<String>>())
    }

    /// Get all pending challenges of `wallet_id` as a [Vec<Vec<String>>]
    /// Returns pairs of [account_type, challenge_token]
    pub async fn get_challenges(
        &mut self,
        network: &str,
        account_id: &AccountId32,
    ) -> anyhow::Result<Vec<Vec<String>>> {
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let pending = state
            .challenges
            .iter()
            .filter(|(_, challenge)| !challenge.done)
            .filter_map(|(acc_type, challenge)| {
                challenge
                    .token
                    .as_ref()
                    .map(|token| vec![acc_type.clone(), token.clone()])
            })
            .collect();

        Ok(pending)
    }

    /// constructing [VerificationFields] object from the registration done of all the accounts
    /// under `wallet_id`
    pub async fn extract_info(
        &mut self,
        network: &str,
        account_id: &AccountId32,
    ) -> anyhow::Result<VerificationFields> {
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(VerificationFields::default()),
        };

        let mut fields = VerificationFields::default();

        for (acc_type, challenge) in &state.challenges {
            if challenge.done {
                match acc_type.as_str() {
                    "discord" => fields.discord = true,
                    "twitter" => fields.twitter = true,
                    "matrix" => fields.matrix = true,
                    "display_name" => fields.display_name = true,
                    "email" => fields.email = true,
                    "github" => fields.github = true,
                    "legal" => fields.legal = true,
                    "web" => fields.web = true,
                    "pgp_fingerprint" => fields.pgp_fingerprint = true,
                    _ => {}
                }
            }
        }

        Ok(fields)
    }

    pub async fn get_challenge_token_from_account_type(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        acc_type: &AccountType,
    ) -> anyhow::Result<Option<Token>> {
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let type_key = acc_type.to_string();

        match state.challenges.get(&type_key) {
            Some(challenge) => Ok(challenge.token.clone().map(Token::new)),
            None => Ok(None),
        }
    }

    pub async fn get_challenge_token_from_account_info(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        account_type: &str,
    ) -> anyhow::Result<Option<Token>> {
        let state = match self.get_verification_state(network, account_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        match state.challenges.get(account_type) {
            Some(challenge) => Ok(challenge.token.clone().map(Token::new)),
            None => Ok(None),
        }
    }

    pub async fn clear_all_related_to(
        &mut self,
        network: &str,
        who: &AccountId32,
    ) -> anyhow::Result<()> {
        let mut pipe = redis::pipe();
        pipe.cmd("DEL")
            .arg(&format!("{}:{}", who.to_string(), network));

        let accounts = self.search(&format!("*:{}:{}", network, who))?;
        for account in accounts {
            pipe.cmd("DEL").arg(account);
        }

        pipe.exec(&mut self.conn)?;
        Ok(())
    }

    pub async fn save_account(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        let mut pipe = redis::pipe();
        for (account, _) in accounts {
            let key = format!("{}:{}:{}", account, network, account_id);
            let pipe = pipe.cmd("SET").arg(&key);
            if let Some(challenge_info) = state.challenges.get(&account.account_type().to_string())
            {
                pipe.arg(&serde_json::to_string(&challenge_info)?);
            }
        }
        let _ = pipe.exec(&mut self.conn);
        Ok(())
    }

    pub async fn save_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        let key = format!("{}:{}", account_id, network);
        let value = serde_json::to_string(&state)?;

        redis::pipe()
            .cmd("SET")
            .arg(&key)
            .arg(value)
            .exec(&mut self.conn)?;

        Ok(())
    }

    pub async fn update_verification_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        self.save_state(network, account_id, state).await?;
        let mut pipe = redis::pipe();
        for (acc_type, info) in state.challenges.clone() {
            let pipe = pipe.cmd("SET");
            // TODO: deal with this clowns
            let acc_key = match acc_type.as_str() {
                "discord" => Account::Discord(info.name.clone()),
                "twitter" => Account::Twitter(info.name.clone()),
                "web" => Account::Web(info.name.clone()),
                "github" => Account::Github(info.name.clone()),
                "email" => Account::Email(info.name.clone()),
                "legal" => Account::Legal(info.name.clone()),
                "matrix" => Account::Matrix(info.name.clone()),
                "pgp_fingerprint" => todo!(),
                _ => unreachable!(),
            };
            let key = format!("{}:{}:{}", acc_key, network, account_id);
            pipe.arg(&key).arg(&serde_json::to_string(&info)?);
        }
        pipe.exec(&mut self.conn)?;
        Ok(())
    }

    pub async fn init_verification_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        state: &AccountVerification,
        accounts: &HashMap<Account, bool>,
    ) -> anyhow::Result<()> {
        self.save_state(network, account_id, state).await?;
        self.save_account(network, account_id, state, accounts)
            .await?;

        Ok(())
    }

    pub async fn get_verification_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
    ) -> anyhow::Result<Option<AccountVerification>> {
        let key = format!("{}:{}", account_id, network);
        info!("key: {}", key);
        let value: Option<String> = self.conn.get(&key)?;

        match value {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    pub async fn update_challenge_status(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        account_type: &str,
    ) -> anyhow::Result<bool> {
        if let Some(mut state) = self.get_verification_state(network, account_id).await? {
            if state.mark_challenge_done(account_type) {
                self.update_verification_state(network, account_id, &state)
                    .await?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub async fn clear_verification_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
    ) -> anyhow::Result<()> {
        let key = format!("{}:{}", account_id, network);
        let _: () = self.conn.del(&key)?;
        Ok(())
    }

    pub async fn process_state_change(
        redis_cfg: &RedisConfig,
        msg: &redis::Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::create_conn(redis_cfg)?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(
            "Processing Redis message - Channel: {}, Payload: {}",
            channel, payload
        );

        // early returns for unsupported operations
        if !matches!(payload.as_str(), "set" | "del") {
            info!("Ignoring Redis operation: {}", payload);
            return Ok(None);
        }

        // extract key from channel name
        let key = match channel.strip_prefix("__keyspace@0__:") {
            Some(k) => k,
            None => return Ok(None),
        };

        // parse network and account ID
        let (account_id, network) = match key.split_once(':') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let id = match AccountId32::from_str(account_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        // get verification state
        let state = match conn.get_verification_state(network, &id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(Some((
            id,
            serde_json::json!({
                "type": "AccountState",
                "network": network,
                "verification_state": state,
                "operation": payload,
            }),
        )))
    }
}
