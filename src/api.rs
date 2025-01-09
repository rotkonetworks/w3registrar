#![allow(dead_code)]

use anyhow::anyhow;
use futures::channel::mpsc::{self, Sender};
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::StreamExt;
use futures_util::SinkExt;
use redis::{self, RedisError};
use redis::{Client as RedisClient, Commands};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use std::str::FromStr;
use sp_core::blake2_256;
use sp_core::Encode;
use subxt::utils::AccountId32;
use tokio::{
    net::TcpStream,
    sync::Mutex,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info};


use crate::config::GLOBAL_CONFIG;


use crate::{
    config::{RedisConfig, WatcherConfig},
    matrix::{self},
    node::{
        self,
        api::runtime_types::{
            pallet_identity::types::{Data as IdentityData, Judgement},
            people_rococo_runtime::people::IdentityInfo,
        },
        filter_accounts,
        identity::events::{JudgementRequested, JudgementUnrequested},
        runtime_types::pallet_identity::types::Registration,
        Client as NodeClient,
    },
    token::AuthToken,
    token::Token,
    Config,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum VerifStatus {
    Done,
    Pending,
}

impl VerifStatus {
    pub async fn set_done(&mut self) -> anyhow::Result<()> {
        *self = Self::Done;
        return anyhow::Result::Ok(());
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AcctMetadata {
    pub status: VerifStatus,
    pub id: AccountId32,
    pub token: Token,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Account {
    Twitter(String),
    Discord(String),
    Matrix(String),
    Display(String),
    Legal(String),
    Web(String),
    Email(String),
    Github(String),
    PGPFingerPrint([u8; 20]),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AccountType {
    Discord,
    Display,
    Email,
    Matrix,
    Twitter,
}

impl AccountType {
    /// Checks if `field` is eq to an account name (discord, twitter, etc)
    /// in a case insensitive manner i.e. "Discord" == "discord" == "DiScOrD"
    /// TODO: use serde :)
    fn from_str(field: &str) -> Option<Self> {
        match field.to_lowercase().as_str() {
            "discord" => Some(AccountType::Discord),
            "display_name" => Some(AccountType::Display),
            "email" => Some(AccountType::Email),
            "matrix" => Some(AccountType::Matrix),
            "twitter" => Some(AccountType::Twitter),
            _ => None,
        }
    }
}

impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let acc = match self {
            Account::Discord(name) => format!("Discord:{}", name),
            Account::Twitter(name) => format!("Twitter:{}", name),
            Account::Matrix(name) => format!("Matrix :{}", name),
            Account::Display(name) => format!("Display :{}", name),
            Account::Legal(name) => format!("Legal :{}", name),
            Account::Web(name) => format!("Web: {}", name),
            Account::Email(name) => format!("Email: {}", name),
            Account::Github(name) => format!("Github: {}", name),
            Account::PGPFingerPrint(fp) => format!("PGPFingerPrint: {:?}", fp),
        };
        serializer.serialize_str(&acc)
    }
}

impl<'de> Deserialize<'de> for Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let acc = String::deserialize(deserializer)?;
        let parts: Option<(&str, &str)> = acc.split_once(':');
        match parts {
            Some((acc_type, acc_name)) => match acc_type {
                "Discord" => Ok(Account::Discord(acc_name.to_owned())),
                "Twitter" => Ok(Account::Twitter(acc_name.to_owned())),
                "Matrix" => Ok(Account::Matrix(acc_name.to_owned())),
                "Email" => Ok(Account::Email(acc_name.to_owned())),
                "Display" => Ok(Account::Display(acc_name.to_owned())),
                "Github" => Ok(Account::Github(acc_name.to_owned())),
                "Legal" => Ok(Account::Legal(acc_name.to_owned())),
                "Web" => Ok(Account::Web(acc_name.to_owned())),
                "PGPFingerPrint" => Err(serde::de::Error::custom("TODO")),
                _ => {
                    return Err(serde::de::Error::custom("Invalid account format"));
                }
            },
            None => return Err(serde::de::Error::custom("Invalid account format")),
        }
    }
}

impl Account {
    /// Derives an [Account] from a String in the following template
    /// <platform>:<acc-name>
    /// TODO: substitute this with deserialization call
    pub fn from_string(value: String) -> Option<Self> {
        match value.split_once(":") {
            Some((l, r)) => {
                info!("\nPlatform: {}\nNick: {}", l, r);
                match &l[1..] {
                    "discord" => Some(Self::Discord(String::from(&r[..r.len() - 1]))),
                    "display_name" => Some(Self::Display(String::from(&r[..r.len() - 1]))),
                    "email" => Some(Self::Email(String::from(&r[..r.len() - 1]))),
                    "matrix" => Some(Self::Matrix(String::from(&r[..r.len() - 1]))),
                    "twitter" => Some(Self::Twitter(String::from(&r[..r.len() - 1]))),
                    _ => return None,
                }
            }
            None => return None,
        }
    }

    pub fn into_accounts(value: &IdentityInfo) -> Vec<Account> {
        let mut result = vec![];
        if let Some(acc) = identity_data_tostring(&value.discord) {
            result.push(Account::Discord(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.twitter) {
            result.push(Account::Twitter(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.matrix) {
            result.push(Account::Matrix(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.email) {
            result.push(Account::Email(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.display) {
            result.push(Account::Display(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.github) {
            result.push(Account::Github(acc))
        }

        if let Some(acc) = identity_data_tostring(&value.legal) {
            result.push(Account::Legal(acc))
        }

        if let Some(acc) = value.pgp_fingerprint {
            result.push(Account::PGPFingerPrint(acc))
        }
        return result;
    }

    pub fn inner(&self) -> String {
        match self {
            Account::Twitter(v) => v.to_owned(),
            Account::Discord(v) => v.to_owned(),
            Account::Matrix(v) => v.to_owned(),
            Account::Display(v) => v.to_owned(),
            Account::Email(v) => v.to_owned(),
            Account::Legal(v) => v.to_owned(),
            Account::Github(v) => v.to_owned(),
            Account::Web(v) => v.to_owned(),
            Account::PGPFingerPrint(v) => String::from_utf8(v.to_vec()).unwrap(),
        }
    }

    pub fn account_type(&self) -> &str {
        match self {
            Self::Discord(_) => "discord",
            Self::Display(_) => "display_name",
            Self::Email(_) => "email",
            Self::Matrix(_) => "matrix",
            Self::Twitter(_) => "twitter",
            _ => "unknown",
        }
    }

    /// constructs a [HashMap] of {Accout: VerifStatus} from a
    /// [Vec<Account>] as `accounts` and a [VerifStatus] as `value`
    pub fn into_hashmap(
        accounts: Vec<Account>,
        value: VerifStatus,
    ) -> HashMap<Account, VerifStatus> {
        let mut result = HashMap::new();
        for account in accounts {
            result.insert(account, value.clone());
        }
        result
    }
}

// --------------------------------------
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubscribeAccountStateRequest {
    #[serde(rename = "type")]
    pub _type: SubscribeAccountState,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub payload: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengedAccount {
    pub account: String,
    pub field: AccountType,
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationRequest {
    #[serde(rename = "type")]
    pub _type: RequestVerificationChallenge,
    pub payload: RequestedAccount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestedAccount {
    pub wallet_id: AccountId32,
    pub field: AccountType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationResponse {
    pub version: String,
    #[serde(rename = "type")]
    pub _type: RequestVerificationChallenge,
    payload: Account,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyIdentityRequest {
    #[serde(rename = "type")]
    pub _type: String,
    pub payload: ChallengedAccount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum WebSocketMessage {
    SubscribeAccountState(SubscribeAccountStateRequest),
    RequestVerificationChallenge(VerificationRequest),
    VerifyIdentity(VerifyIdentityRequest),
    NotifyAccountState(NotifyAccountState),
    JsonResult(JsonResult),
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionedMessage {
    pub version: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub payload: serde_json::Value,
}

// ------------------
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SubscribeAccountState {
    SubscribeAccountState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RequestVerificationChallenge {
    RequestVerificationChallenge,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VerifyIdentity {
    VerifyIdentity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum JsonResult {
    JsonResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NotifyAccountState {
    NotifyAccountState,
}
// --------------------------------------

/// Spawns the Websocket client, Matrix client and the Node(substrate) listener
pub async fn spawn_services(cfg: Config) -> anyhow::Result<()> {
    info!("Starting services...");

    // Spawn node listener first
    info!("Spawning node listener...");
    spawn_node_listener().await?;
    info!("Node listener spawned successfully");

    // Spawn websocket server
    info!("Spawning websocket server...");
    spawn_ws_serv().await?;
    info!("Websocket server spawned successfully");

    // Matrix bot is currently disabled
    // matrix::start_bot(cfg.matrix, &cfg.redis, &cfg.watcher).await?;

    info!("All services started successfully");
    Ok(())
}

pub async fn spawn_node_listener() -> anyhow::Result<()> {
//    TODO:  work
    Ok(())
}

/// Converts the inner of [IdentityData] to a [String]
pub fn identity_data_tostring(data: &IdentityData) -> Option<String> {
    info!("Data: {:?}", data);
    match data {
        IdentityData::Raw0(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw1(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw2(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw3(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw4(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw5(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw6(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw7(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw8(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw9(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw10(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw11(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw12(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw13(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw14(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw15(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw16(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw17(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw18(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw19(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw20(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw21(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw22(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw23(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw24(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw25(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw26(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw27(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw28(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw29(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw30(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw31(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw32(v) => Some(String::from_utf8_lossy(v).to_string()),
        _ => None,
    }
}

/// helper function to deserialize SS58 string into AccountId32
fn ss58_to_account_id32<'de, D>(deserializer: D) -> Result<AccountId32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ss58: String = Deserialize::deserialize(deserializer)?;
    AccountId32::from_str(&ss58)
        .map_err(|e| serde::de::Error::custom(format!("Invalid SS58: {e:?}")))
}

fn string_to_account_id(s: &str) -> anyhow::Result<AccountId32> {
    AccountId32::from_str(s).map_err(|e| anyhow!("Invalid account ID: {}", e))
}

#[derive(Debug, Clone)]
struct Listener {
    redis_cfg: RedisConfig,
    socket_addr: SocketAddr,
}

impl Listener {
    pub async fn new() -> Self {
        let cfg = GLOBAL_CONFIG.lock().await;
        Self {
            redis_cfg: cfg.redis.clone(),
            socket_addr: cfg.websocket.socket_addrs().unwrap(),
        }
    }

    pub async fn handle_subscription_request(
        &mut self,
        request: SubscribeAccountStateRequest,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        *subscriber = Some(request.payload.clone());
        let redis_cfg = &self.redis_cfg;
        let cfg = GLOBAL_CONFIG.lock().await;

        // Connect to the node to get registration info
        let client = NodeClient::from_url(&cfg.watcher.endpoint).await?;
        let registration = node::get_registration(&client, &request.payload).await?;

        // Connect to Redis
        let mut conn = RedisConnection::create_conn(redis_cfg)?;

        // Clear existing data for this account
        conn.clear_all_related_to(&request.payload).await?;

        let accounts = filter_accounts(
            &registration.info,
            &request.payload,
            cfg.watcher.registrar_index,
            &cfg.watcher.endpoint
        ).await?;

        // Process accounts and store in Redis
        for (account, status) in &accounts {
            if !matches!(status, VerifStatus::Pending) {
                continue;
            }

            let account_key = match account {
                Account::Display(name) => {
                    // Just store the name without any challenge token
                    let key = format!("Display:{}:{}", name, request.payload);
                    redis::pipe()
                        .cmd("HSET")
                        .arg(&key)
                        .arg("status")
                        .arg(serde_json::to_string(&status)?)
                        .arg("wallet_id") 
                        .arg(request.payload.to_string())
                        .exec(&mut conn.conn)?;
                    key
                },
                Account::Discord(name) => format!("Discord:{}:{}", name, request.payload),
                Account::Twitter(name) => format!("Twitter:{}:{}", name, request.payload),
                Account::Matrix(address) => format!("Matrix:{}:{}", address, request.payload),
                // TODO:email inbound verified(string input to us)
                Account::Email(address) => format!("Email:{}:{}", address, request.payload),
                // Account::Github(name) => format!("Github:{}:{}", name, request.payload),
                // Account::Web(name) => format!("Web:{}:{}", name, request.payload),
                // Account::PGPFingerPrint(key) => format!("PGPFingerPrint:{}:{}", key, request.payload),
                Account::Github(_) => continue,
                Account::Legal(_) => continue, // not supported
                Account::Web(_) => continue,
                Account::PGPFingerPrint(_) => continue,
            };

            // Only generate and store token for non-Display accounts
            if !matches!(account, Account::Display(_)) {
                let token = Token::generate().await;
                redis::pipe()
                    .cmd("HSET")
                    .arg(&account_key)
                    .arg("status")
                    .arg(serde_json::to_string(&status)?)
                    .arg("wallet_id") 
                    .arg(request.payload.to_string())
                    .arg("token")
                    .arg(token.show())
                    .exec(&mut conn.conn)?;

                info!("Saved challenge token {} for account {}", token.show(), account_key);
            }
        }

        // Store overall account status
        redis::pipe()
            .cmd("HSET")
            .arg(serde_json::to_string(&request.payload)?)
            .arg("accounts")
            .arg(serde_json::to_string(&accounts)?)
            .arg("status")
            .arg(serde_json::to_string(&VerifStatus::Pending)?)
            .exec(&mut conn.conn)?;

        Ok(serde_json::json!({
            "type": "ok",
            "message": {
                "info": conn.extract_info(&request.payload)?,
                "hash": format!("0x{}", hex::encode(blake2_256(&registration.info.encode()))),
                "pending_challenges": conn.get_challenges(&request.payload)?,
                "account": request.payload.to_string()
            }
        }))
    }

    /// Generates a hex-encoded blake2 hash of the identity info with 0x prefix
    fn hash_identity_info(&self, info: &IdentityInfo) -> String {
        let encoded_info = info.encode();
        let hash = blake2_256(&encoded_info);
        format!("0x{}", hex::encode(hash))
    }

    async fn process_v1(
        &mut self,
        message: VersionedMessage,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        match message.message_type.as_str() {
            "SubscribeAccountState" => {
                let payload = message.payload.as_str()
                    .ok_or_else(|| anyhow!("Payload must be a string"))?;
                let account_id = AccountId32::from_str(payload)
                    .map_err(|e| anyhow!("Invalid account ID: {}", e))?;

                let req = SubscribeAccountStateRequest {
                    _type: SubscribeAccountState::SubscribeAccountState,
                    payload: account_id,
                };

                self.handle_subscription_request(req, subscriber).await
            },
            "VerifyIdentity" => {
                let verify_request: ChallengedAccount = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid VerifyIdentity payload: {}", e))?;

                let internal_request = VerifyIdentityRequest {
                    _type: "VerifyIdentity".to_string(),
                    payload: verify_request,
                };

                self.handle_identity_verification_request(internal_request).await
            },
            _ => Err(anyhow!("Unsupported message type: {}", message.message_type)),
        }
    }

    async fn _handle_incoming(
        &mut self,
        message: tokio_tungstenite::tungstenite::Message,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        if let Message::Text(text) = message {
            match serde_json::from_str::<VersionedMessage>(&text) {
                Ok(versioned_msg) => {
                    match versioned_msg.version.as_str() {
                        "1.0" => {
                            match self.process_v1(versioned_msg, subscriber).await {
                                Ok(response) => Ok(response),
                                Err(e) => Ok(serde_json::json!({
                                    "type": "error",
                                    "message": e.to_string()
                                }))
                            }
                        },
                        _ => Ok(serde_json::json!({
                            "type": "error",
                            "message": format!("Unsupported version: {}", versioned_msg.version)
                        }))
                    }
                }
                Err(e) => {
                    Ok(serde_json::json!({
                        "type": "error",
                        "message": format!("Failed to parse message: {}", e)
                    }))
                }
            }
        } else {
            Ok(serde_json::json!({
                "type": "error",
                "message": "Unsupported message format"
            }))
        }
    }

    // TODO: check if Judgement is requested (JudgementRequested)
    /// checks if the registration request is well synchronized with the registrar node
    pub async fn check_node(
        id: AccountId32,
        accounts: Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        let client = NodeClient::from_url("wss://dev.rotko.net/people-rococo").await?;
        let registration = node::get_registration(&client, &id).await;
        info!("registration: {:#?}", registration);
        match registration {
            Ok(reg) => {
                Self::is_complete(&reg, &accounts)?;
                Self::has_paid_fee(reg.judgements.0)?;
                Ok(())
            }
            Err(_) => Err(anyhow!(
                    "coudn't get registration of {} from the BC node",
                    id
            )),
        }
    }

    /// Checks if fee is paid
    /// TODO: migrate this to a common module
    fn has_paid_fee(judgements: Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
        if judgements
            .iter()
                .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
        {
            Ok(())
        } else {
            Err(anyhow!("fee is not paid!"))
        }
    }

    /// Compares between the accounts on the idendtity object on the check_node
    /// and the received requests
    /// TODO: migrate this to a common module
    pub fn is_complete<'a>(
        registration: &Registration<u128, IdentityInfo>,
        expected: &Vec<Account>,
    ) -> anyhow::Result<(), anyhow::Error> {
        for acc in expected {
            let (stored_acc, expected_acc) = match acc {
                Account::Discord(discord_acc) => (
                    identity_data_tostring(&registration.info.discord),
                    discord_acc,
                ),
                Account::Display(display_name) => (
                    identity_data_tostring(&registration.info.display),
                    display_name,
                ),
                Account::Matrix(matrix_acc) => (
                    identity_data_tostring(&registration.info.matrix),
                    matrix_acc,
                ),
                Account::Twitter(twit_acc) => (
                    identity_data_tostring(&registration.info.twitter),
                    twit_acc,
                ),
                _ => todo!(),
            };

            let stored_acc = stored_acc.ok_or_else(|| {
                anyhow!("{} acc {} not in identity obj", acc.account_type(), expected_acc)
            })?;

            if !expected_acc.eq(&stored_acc) {
                return Err(anyhow!("got {}, expected {}", expected_acc, stored_acc));
            }
        }
        Ok(())
    }

    async fn monitor_hash_changes(client: RedisClient, key: String) -> Option<String> {
        let mut pubsub = client.get_async_pubsub().await.unwrap();
        let channel = format!("__keyspace@0__:{}", key);
        pubsub.subscribe(channel).await.unwrap();
        while let Some(_) = pubsub.on_message().next().await {
            let mut con = client.get_connection().unwrap();
            let status: String = con.hget(&key, String::from("status")).unwrap();
            let status: VerifStatus = serde_json::from_str(&status).unwrap();
            match status {
                VerifStatus::Done => {
                    return Some(String::from("Done"));
                }
                _ => {}
            }
        }
        return None;
    }

    pub async fn handle_identity_verification_request(
        &self,
        request: VerifyIdentityRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let account_id = string_to_account_id(&request.payload.account)?;
        // TODO: Add networks polkadot/kusama/paseo/rococo
        let challenge_identifier = format!("{}:{:?}", 
            request.payload.account,
            request.payload.field
        );
        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;

        match conn.get_challenge_token_from_account_type(&account_id, &request.payload.field)? {
            Some(challenge) => {
                if request.payload.challenge.eq(&challenge.show()) {
                    Ok(serde_json::json!({
                        "type": "ok",
                        "message": true,
                    }))
                } else {
                    Ok(serde_json::json!({
                        "type": "error",
                        "reason": format!(
                            "{} is not equal to the challenge of {}",
                            challenge.show(),
                            challenge_identifier
                        ),
                    }))
                }
            }
            None => {
                Ok(serde_json::json!({
                    "type": "error",
                    "reason": format!("could not find challenge for {}", challenge_identifier),
                }))
            }
        }
    }

    pub async fn filter_message(message: &Message) -> Option<AccountId32> {
        if let Message::Text(text) = message {
            let parsed: VersionedMessage = serde_json::from_str(text).ok()?;
            let account_str = parsed.payload.as_str()?;
            return AccountId32::from_str(account_str).ok();
        }
        None
    }

    async fn save_conns(
        &mut self,
        message: &Message,
        out: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    ) {
        todo!()
    }

    pub async fn spawn_node_listener() -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG.lock().await;

        let listener = NodeListener::new(cfg.watcher.clone(), cfg.redis.clone()).await?;

        tokio::spawn(async move {
            if let Err(e) = listener.listen().await {
                tracing::error!("Error in node listener: {:?}", e);
            }
        });

        Ok(())
    }

    async fn send_message(write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>, msg: String) -> Result<(), anyhow::Error> {
        let mut guard = write.lock().await;
        guard.send(Message::Text(msg)).await?;
        Ok(())
    }

    async fn process_websocket(
        &mut self,
        write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut read: SplitStream<WebSocketStream<TcpStream>>,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                // Handle messages sent to this task via the `sender` channel
                Some(msg) = receiver.next() => {
                    // Prepare the response
                    let response = serde_json::json!({
                        "version": "1.0",
                        "payload": msg
                    });

                    // Serialize and send the message
                    let serialized = match serde_json::to_string(&response) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to serialize response: {}", e);
                            continue;
                        }
                    };

                    if let Err(e) = Self::send_message(&write, serialized).await {
                        error!("Failed to send message: {}", e);
                        break;
                    }
                }

                // Handle incoming WebSocket messages
                Some(msg_result) = read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            info!("WebSocket connection closed");
                            break;
                        }
                        Ok(msg) => {
                            // Process the incoming message
                            match self._handle_incoming(msg, &mut subscriber).await {
                                Ok(response) => {
                                    let formatted_response = serde_json::json!({
                                        "version": "1.0",
                                        "payload": response
                                    });

                                    // Serialize and send the response
                                    let serialized = match serde_json::to_string(&formatted_response) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            error!("Failed to serialize response: {}", e);
                                            continue;
                                        }
                                    };

                                    if let Err(e) = Self::send_message(&write, serialized).await {
                                        error!("Failed to send response: {}", e);
                                        break;
                                    }

                                    // Handle new subscribers and spawn Redis listener
                                    if let Some(id) = subscriber.take() {
                                        info!("New subscriber: {:?}", id);
                                        let mut cloned_self = self.clone();
                                        let sender = sender.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = cloned_self.spawn_redis_listener(sender, id).await {
                                                error!("Redis listener error: {}", e);
                                            }
                                        });
                                    }
                                }
                                Err(e) => {
                                    error!("Error handling message: {}", e);
                                    let error_response = serde_json::json!({
                                        "version": "1.0",
                                        "error": e.to_string()
                                    });

                                    // Serialize and send the error response
                                    let serialized = match serde_json::to_string(&error_response) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            error!("Failed to serialize error response: {}", e);
                                            continue;
                                        }
                                    };

                                    if let Err(e) = Self::send_message(&write, serialized).await {
                                        error!("Failed to send error response: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                    }
                }

                // Fallback case if no other branches are matched
                else => {
                    error!("Unexpected end of message streams");
                    break;
                }
            }
        }
    }

    /// Handles incoming websocket connection
    pub async fn handle_connection(&mut self, stream: std::net::TcpStream) {
        let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to convert to tokio TcpStream: {}", e);
                return;
            }
        };

        let ws_stream = match tokio_tungstenite::accept_async(tokio_stream).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("WebSocket handshake failed: {}", e);
                return;
            }
        };

        info!("WebSocket connection established");
        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        self.process_websocket(write, read).await;
        info!("WebSocket connection closed");
    }

    // Replace the current listen method with this:
    pub async fn listen(&mut self) -> ! {
        let listener = match tokio::net::TcpListener::bind(self.socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind to address: {}", e);
                std::process::exit(1);
            }
        };
        info!("WebSocket server listening on {}", self.socket_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Incoming connection from {:?}...", addr);
                    let mut clone = self.clone();
                    tokio::spawn(async move {
                        clone.handle_connection(stream.into_std().unwrap()).await;
                    });
                    info!("Connection handler spawned");
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn spawn_redis_listener(
        &mut self,
        mut sender: Sender<serde_json::Value>,
        account: AccountId32,
    ) -> anyhow::Result<()> {
        let redis_cfg = self.redis_cfg.clone();
        info!("Starting Redis listener task!");

        tokio::spawn(async move {
            let client = match RedisClient::open(redis_cfg.url().unwrap()) {
                Ok(client) => client,
                Err(e) => {
                    error!("Failed to open Redis connection: {:?}", e);
                    return;
                }
            };

            let mut conn = match client.get_connection() {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to get Redis connection: {:?}", e);
                    return;
                }
            };

            let mut pubsub = conn.as_pubsub();

            let channel = format!(
                "__keyspace@0__:{}",
                serde_json::to_string(&account).unwrap()
            );

            info!("Subscribing to channel: {}", channel);
            if let Err(e) = pubsub.subscribe(&channel) {
                error!("Failed to subscribe to channel: {:?}", e);
                return;
            }

            if let Err(e) = sender.send(serde_json::json!({
                "status": "listener_started",
                "channel": channel
            })).await {
                error!("Failed to send test message: {:?}", e);
                return;
            }

            info!("Starting message processing loop");
            loop {
                match pubsub.get_message() {
                    Ok(msg) => {
                        info!("Redis event received: {:?}", msg);
                        let result = process_redis_account_change(&redis_cfg, msg).await;
                        if let Some((_, obj)) = result {
                            if let Err(e) = sender.send(obj).await {
                                error!("Failed to send message: {:?}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error getting Redis message: {:?}", e);
                        break;
                    }
                }
            }
            info!("Redis listener loop ended");
        });

        info!("Redis listener task spawned");
        Ok(())
    }
}

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv() -> anyhow::Result<()> {
    let mut listener = Listener::new().await;
    listener.listen().await;

    Ok(())
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
struct NodeListener {
    client: NodeClient,
    redis_cfg: RedisConfig,
    reg_index: u32,
    endpoint: String,
}

impl NodeListener {
    /// Creates a new [NodeListener]
    ///
    /// # Panics
    /// This function will fail if the _redis_url_ is an invalid url to a redis server
    /// or if _node_url_ is not a valid url for a substrate BC node
    pub async fn new(cfg: WatcherConfig, redis_cfg: RedisConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: NodeClient::from_url(&cfg.endpoint).await?,
            redis_cfg,
            reg_index: cfg.registrar_index,
            endpoint: cfg.endpoint,
        })
    }

    /// Listens for incoming events on the substrate node, in particular
    /// the `requestJudgement` event
    pub async fn listen(self) -> anyhow::Result<()> {
        let mut block_stream = self.client.blocks().subscribe_finalized().await?;
        tokio::spawn(async move {
            while let Some(item) = block_stream.next().await {
                let block = item.unwrap();
                for event in block.events().await.unwrap().iter() {
                    let event = event.unwrap();
                    // TODO: check for cancleRequest calls
                    match event.as_event::<JudgementRequested>() {
                        Ok(Some(req)) => {
                            // TODO: check the registrar index
                            let clone = self.clone();
                            tokio::spawn(async move {
                                info!("Judgement requested by {}", req.who);
                                info!("status: {:?}", clone.handle_registration(&req.who).await);
                            });
                        }
                        _ => {}
                    }

                    match event.as_event::<JudgementUnrequested>() {
                        Ok(Some(req)) => {
                            let clone = self.clone();
                            tokio::spawn(async move {
                                info!("Judgement unrequested by {}", req.who);
                                info!("status: {:?}", clone.cancel_registration(&req.who).await);
                            });
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(())
    }

    /// Handles incoming registration request via the `JudgementRequested` event by first checking
    /// if the requested fields/accounts can be verified, and if so, saves the registration request
    /// to `redis` as `Pending` otherwise, issue `Erroneous` judgement and save the registration
    /// request as `Done`
    ///
    /// # Note
    /// For now, we only handle registration requests from `Matrix`, `Twitter` and `Discord`
    async fn handle_registration(&self, who: &AccountId32) -> anyhow::Result<(), anyhow::Error> {
        let registration = node::get_registration(&self.client, who).await;
        match registration {
            Ok(reg) => {
                Listener::has_paid_fee(reg.judgements.0)?;
                let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;
                conn.clear_all_related_to(who).await?;

                let cfg = GLOBAL_CONFIG.lock().await;
                let accounts =
                    filter_accounts(&reg.info,
                        who,
                        cfg.watcher.registrar_index,
                        &cfg.watcher.endpoint
                    ).await?;

                // TODO: make all commands chained together and then executed
                // all at once!
                redis::pipe()
                    .cmd("HSET")
                    .arg(serde_json::to_string(who)?)
                    .arg("accounts")
                    .arg(serde_json::to_string(&accounts)?)
                    .arg("status")
                    .arg(serde_json::to_string(&VerifStatus::Pending)?)
                    .exec(&mut conn.conn)?;

                for (account, status) in accounts {
                    match status {
                        VerifStatus::Done => {
                            redis::cmd("HSET")
                                .arg(format!(
                                        "{}:{}",
                                        serde_json::to_string(&account)?,
                                        serde_json::to_string(who)?
                                ))
                                .arg("status")
                                .arg(serde_json::to_string(&status)?)
                                .arg("wallet_id")
                                .arg(serde_json::to_string(who)?)
                                .arg("token")
                                .arg::<Option<String>>(None)
                                .exec(&mut conn.conn)?;
                            }
                        VerifStatus::Pending => {
                            redis::cmd("HSET")
                                .arg(format!(
                                        "{}:{}",
                                        serde_json::to_string(&account)?,
                                        serde_json::to_string(who)?
                                ))
                                .arg("status")
                                .arg(serde_json::to_string(&status)?)
                                .arg("wallet_id")
                                .arg(serde_json::to_string(who)?)
                                .arg("token")
                                .arg(Some(Token::generate().await.show()))
                                .exec(&mut conn.conn)?;
                            }
                    }
                }
                return Ok(());
            }
            Err(_) => return Err(anyhow!("could not get registration for {}", who)),
        }
    }

    /// Cancels the pending registration requests issued by `who` by removing it's occurance on
    /// our `redis` server.
    ///
    /// # Note
    /// this method should be used in conjunction with the `JudgementUnrequested` event
    async fn cancel_registration(&self, who: &AccountId32) -> anyhow::Result<(), anyhow::Error> {
        let mut conn = RedisConnection::create_conn(&self.redis_cfg)?;
        conn.clear_all_related_to(who).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationFields {
    pub discord: bool,
    pub twitter: bool,
    pub matrix: bool,
    pub email: bool,
    pub display: bool,
    pub github: bool,
    pub legal: bool,
    pub web: bool,
    pub pgp_fingerprint: bool,
}

impl Default for VerificationFields {
    fn default() -> Self {
        Self {
            matrix: false,
            display: false,
            discord: false,
            email: false,
            twitter: false,
            github: false,
            web: false,
            pgp_fingerprint: false,
            legal: false,
        }
    }
}

pub struct RedisConnection {
    conn: redis::Connection,
}

impl RedisConnection {
    pub fn create_conn(addr: &RedisConfig) -> anyhow::Result<Self> {
        let client = RedisClient::open(addr.url()?)
            .map_err(|e| anyhow!("Cannot open Redis client: {}", e))?;

        let mut conn = client.get_connection()
            .map_err(|e| anyhow!("Cannot establish Redis connection: {}", e))?;

        RedisConnection::enable_keyspace_notifications(&mut conn)?;

        Ok(Self { conn })
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
        let related_keys = self.search(format!("*:{}", serde_json::to_string(&account_id)?))?;
        let mut pubsub = self.conn.as_pubsub();

        for key in related_keys {
            let channel = format!("__keyspace@0__:{}", key);
            pubsub.subscribe(&channel)?;
        }

        Ok(pubsub)
    }

    /// Search through the redis for keys that are similar to the `pattern`
    pub fn search(&mut self, pattern: String) -> anyhow::Result<Vec<String>> {
        Ok(self
            .conn
            .scan_match::<&str, String>(&pattern)?
            .collect::<Vec<String>>())
    }

    /// Get all pending challenges of `wallet_id` as a [Vec<Vec<String>>]
    /// Returns pairs of [account_type, challenge_token]
    pub fn get_challenges(&mut self, wallet_id: &AccountId32) -> anyhow::Result<Vec<Vec<String>>> {
        let wallet_id_str = serde_json::to_string(wallet_id)?;

        Ok(self
            .get_accounts_from_status(wallet_id, VerifStatus::Pending)
            .into_iter()
            .filter_map(|account| {
                let info = format!(
                    "{}:{}",
                    serde_json::to_string(&account).ok()?,
                    wallet_id_str
                );

                match self.get_challenge_token_from_account_info(&info).unwrap() {
                    Some(token) => Some(vec![account.account_type().to_owned(), token.show()]),
                    None => None,
                }
            })
            .collect::<Vec<Vec<String>>>())
    }

    /// constructing [VerificationFields] object from the registration status of all the accounts
    /// under `wallet_id`
    pub fn extract_info(&mut self, wallet_id: &AccountId32) -> anyhow::Result<VerificationFields> {
        let accounts: String = self
            .conn
            .hget(serde_json::to_string(&wallet_id)?, "accounts")?;
        info!("Accounts: {}", accounts);
        let accounts: HashMap<Account, VerifStatus> = serde_json::from_str(&accounts)?;
        info!("Accounts: {:?}", accounts);
        let mut verif_state = VerificationFields::default();

        for (account, acc_state) in accounts {
            if acc_state == VerifStatus::Done {
                // TODO: check this
                match account {
                    Account::Discord(_) => {
                        verif_state.discord = true;
                    }
                    Account::Display(_) => {
                        verif_state.display = true;
                    }
                    Account::Email(_) => {
                        verif_state.email = true;
                    }
                    Account::Twitter(_) => {
                        verif_state.twitter = true;
                    }
                    Account::Matrix(_) => {
                        verif_state.matrix = true;
                    }
                    _ => {}
                }
            }
        }
        Ok(verif_state)
    }

    /// check if redis has hashset with names similar to the `pattern`
    pub fn contains(&mut self, pattern: &str) -> bool {
        let mut res = self.conn.scan_match::<&str, String>(pattern).unwrap();
        if let Some(_) = res.next() {
            return true;
        }
        return false;
    }

    /// Get the challenge [Token] from a hashset with `account` as a name, `token`
    /// as the key paire of the desired token
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format since an
    /// `account` could be verified by differnt `wallet`s
    ///
    /// # Example
    /// ``` ignore
    /// get_challenge_token_from_account(
    ///     AccountId32([0u8; 32]),
    ///     AccountType::Twitter,
    /// );
    /// ```
    pub fn get_challenge_token_from_account_type(
        &mut self,
        wallet_id: &AccountId32,
        acc_type: &AccountType,
    ) -> anyhow::Result<Option<Token>> {
        // Helper closure to create account key
        let make_info = |account: &Account| -> anyhow::Result<String> {
            Ok(format!(
                    "{}:{}",
                    serde_json::to_string(account)?,
                    serde_json::to_string(wallet_id)?
            ))
        };

        let accounts: Vec<Account> = self
            .get_accounts(&wallet_id)?
            .unwrap_or(HashMap::default())
            .keys()
            .cloned()
            .collect();

        let matching_account = accounts.into_iter().find(move |account| {
            matches!(
                (acc_type, account),
                (AccountType::Discord, Account::Discord(_))
                | (AccountType::Display, Account::Display(_))
                | (AccountType::Email, Account::Email(_))
                | (AccountType::Matrix, Account::Matrix(_))
                | (AccountType::Twitter, Account::Twitter(_))
            )
        });

        // If we found a matching account, get its token
        match matching_account {
            Some(account) if matches!(account, Account::Display(_)) => {
                // NOTE:For display names, we only check they exists onchain
                Ok(None)
            }
            Some(account) => {
                let info = make_info(&account)?;
                Ok(self.get_challenge_token_from_account_info(&info)?)
            }
            None => Ok(None),
        }
    }

    /// Get the challenge [Token] from a hashset with `account` as a name, `token`
    /// as the key paire of the desired token
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format since an
    /// `account` could be verified by differnt `wallet`s
    ///
    /// <Discord-Twitter>:{account_name}:{wallet_id}
    ///
    /// # Example
    /// ``` ignore
    /// get_challenge_token_from_account(
    ///     &format!(
    ///         "{}:{}",
    ///         serde_json::to_string(&Account::Twitter("asdf")).?,
    ///         serde_json::to_string(AccountId32([0u8; 32]))?,
    ///     );
    /// )
    /// ```
    pub fn get_challenge_token_from_account_info(
        &mut self,
        account: &str,
    ) -> anyhow::Result<Option<Token>> {
        match self
            .conn
            .hget::<&str, &str, Option<String>>(account, "token")
            {
                Ok(Some(token)) => Ok(Some(Token::new(token))),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow!(
                        "Couldn't retrive challenge for {}\nError {:?}",
                        account,
                        e
                )),
            }
    }

    /// Get the [AccountId32] from a hashset with `account` as a name, `wallet_id`
    /// as the key paire of the desired wallet id
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn get_wallet_id(&mut self, account: &str) -> AccountId32 {
        let account = self
            .conn
            .hget::<&str, &str, String>(account, "wallet_id")
            .unwrap();
        serde_json::from_str(&account).unwrap()
    }

    /// Get the status [VerifStatus] from a hashset with `account` as a name, `status`
    /// as the key paire of the desired status
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    ///
    /// # Return
    /// `Ok(Some(VerifStatus))` - Account exist and no error occured
    /// `Ok(None)` - Account does not exist exist and no error occured
    /// `Err(e)` - Error occured
    pub fn get_status(&mut self, account: &str) -> anyhow::Result<Option<VerifStatus>> {
        match self
            .conn
            .hget::<&str, &str, Option<String>>(account, "status")
            {
                Ok(Some(status)) => Ok(Some(serde_json::from_str::<VerifStatus>(&status)?)),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow!(
                        "Error getting status for {}\nError: {:?}",
                        account,
                        e
                )),
            }
    }

    /// Set the `status` value of a redis hashset of name `account` to the value of
    /// `status` param, and synchronizing with it's corresponding `wallet_id` hashset
    ///
    /// # Note:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    ///
    /// # Example
    /// ```ignore
    /// // TODO
    /// ```
    pub fn set_status(&mut self, account: &str, status: VerifStatus) -> anyhow::Result<()> {
        info!("setting {}, 'status' to {:?}", account, status);
        self.conn.hset::<&str, &str, String, ()>(
            // this acount is in format "{platform}:{acc_name}":"{wallet_id}"
            account,
            "status",
            serde_json::to_string(&status)?,
        )?;

        let wallet_id = self.conn.hget::<&str, &str, String>(account, "wallet_id")?;
        let wallet_id: AccountId32 = serde_json::from_str(&wallet_id)?;
        info!("{:?}", account.rsplit_once(':'));
        let account = serde_json::from_str::<Account>(account.rsplit_once(':').unwrap().0)?;
        self.set_acc_done(&wallet_id, &account)?;
        Ok(())
    }

    /// Checks if all accounts under the hashset of the `id` key is verified
    pub fn is_all_verified(&mut self, id: &AccountId32) -> anyhow::Result<bool> {
        let metadata: String = self.conn.hget(&serde_json::to_string(id)?, "accounts")?;
        let metadata: HashMap<Account, VerifStatus> = serde_json::from_str(&metadata)?;
        for status in metadata.values() {
            match status {
                VerifStatus::Pending => return Ok(false),
                VerifStatus::Done => {}
            }
        }
        return Ok(true);
    }

    /// Set the status field of a hashset with `id` as a name to [VerifStatus::Done]
    ///
    /// # NOTE:
    /// The `account` should be in the "[Account]:[AccountId32]" format
    pub fn signal_done(&mut self, wallet_id: &AccountId32) -> anyhow::Result<()> {
        self.conn.hset::<String, &str, String, ()>(
            serde_json::to_string(&wallet_id)?,
            "status",
            serde_json::to_string(&VerifStatus::Done)?,
        )?;
        Ok(())
    }

    /// sets the status of the `account` under the hashset of name `wallet_id` to [VerifStatus::Done]
    fn set_acc_done(&mut self, wallet_id: &AccountId32, account: &Account) -> anyhow::Result<()> {
        let metadata: String = self
            .conn
            .hget(&serde_json::to_string(wallet_id)?, "accounts")?;
        let mut metadata: HashMap<Account, VerifStatus> = serde_json::from_str(&metadata)?;
        metadata.insert(account.to_owned(), VerifStatus::Done);

        self.conn.hset::<String, &str, String, ()>(
            serde_json::to_string(&wallet_id)?,
            "accounts",
            serde_json::to_string(&metadata)?,
        )?;
        Ok(())
    }

    /// Get all known accounts linked to the `wallet_id` without regard to its registration  status
    ///
    /// # Note
    /// This DOES NOT query anything from the peoples network, rather it gets its info from the
    /// `redis` server
    pub fn get_accounts(
        &mut self,
        wallet_id: &AccountId32,
    ) -> anyhow::Result<Option<HashMap<Account, VerifStatus>>, RedisError> {
        self.conn
            .hget::<&str, &str, String>(&serde_json::to_string(wallet_id)?, "accounts")
            .map(|metadata| {
                serde_json::from_str::<Option<HashMap<Account, VerifStatus>>>(&metadata)
                    .unwrap_or(None)
            })
    }

    /// Get all known accounts linked to the `wallet_id` with a rgistration status equal to `status`
    ///
    /// # Note
    /// This DOES NOT querry anything from the peoples network, rather it gets its info from the
    /// `redis` server
    pub fn get_accounts_from_status(
        &mut self,
        wallet_id: &AccountId32,
        status: VerifStatus,
    ) -> Vec<Account> {
        match self
            .conn
            .hget::<&str, &str, String>(&serde_json::to_string(wallet_id).unwrap(), "accounts")
            {
                Ok(metadata) => {
                    let mut result = vec![];
                    let metadata: HashMap<Account, VerifStatus> =
                        serde_json::from_str(&metadata).unwrap();
                    for (acc, current_status) in metadata {
                        if current_status == status {
                            result.push(acc);
                        }
                    }
                    return result;
                }
                _ => {
                    vec![]
                }
            }
    }

    async fn clear_all_related_to(&mut self, who: &AccountId32) -> anyhow::Result<()> {
        redis::pipe()
            .cmd("DEL")
            .arg(&serde_json::to_string(who)?)
            .exec(&mut self.conn)?;

        let accounts = self.search(format!("*:{}", serde_json::to_string(&who)?))?;
        for account in accounts {
            redis::pipe()
                .cmd("DEL")
                .arg(format!("{}", account))
                .exec(&mut self.conn)?;
            }
        Ok(())
    }

    /// Check if the `account` is verified, this is done only through checking
    /// the `status` field of the hashset of name `account`
    ///
    /// # Note:
    /// The `account` param should be in the "[Account]:[AccountId32]" format
    ///
    /// # Return
    /// `Ok(Some(true))` - Account exist and is verified
    /// `Ok(Some(false))` - Account exist and is not verified
    /// `Ok(None)` - Account does not exist
    /// `Err(e)` - Error occurred
    pub fn is_verified(&mut self, account: &str) -> anyhow::Result<Option<bool>> {
        Ok(self
            .get_status(account)?
            .map(|status| matches!(status, VerifStatus::Done)))
    }

    /// checks if the hashshet of name `account` is in consistent with it's corresponding
    /// hashset of name `wallet_id` where as the `account` is consistent of both [Account] and
    /// [AccountId32]
    //
    /// # Note:
    /// The `account` param should be in the "[Account]:[AccountId32]" format
    pub fn is_consistent(&mut self, account: &str) -> anyhow::Result<Option<bool>> {
        if let Some((acc, wallet_id)) = account.rsplit_once(':') {
            let acc = serde_json::from_str::<Account>(acc)?;
            if let Some(lstatus) = self
                .get_accounts(&serde_json::from_str(wallet_id)?)?
                    .unwrap_or(HashMap::default())
                    .get(&acc)
            {
                let rstatus: String = self.conn.hget(account, "status")?;
                let rstatus: VerifStatus = serde_json::from_str(&rstatus)?;
                return Ok(Some(matches!(rstatus, lstatus)));
            }
        }
        Ok(None)
    }
}


async fn process_redis_account_change(
    redis_cfg: &RedisConfig,
    msg: redis::Msg,
) -> Option<(AccountId32, serde_json::Value)> {
    let mut conn = RedisConnection::create_conn(redis_cfg).ok()?;
    let payload: String = msg.get_payload().ok()?;
    let channel = msg.get_channel_name();

    info!("Processing Redis message - Channel: {}, Payload: {}", channel, payload);

    if !matches!(payload.as_str(), "hset" | "hdel" | "del") {
        info!("Ignoring Redis operation: {}", payload);
        return None;
    }

    let key = channel.strip_prefix("__keyspace@0__:")?;

    // main account key case
    if let Ok(id) = serde_json::from_str::<AccountId32>(key) {
        let accounts = conn.get_accounts(&id).ok()??;
        let status: String = conn.conn.hget(key, "status").ok()?;
        let status = serde_json::from_str(&status).ok()?;

        return Some((
                id,
                serde_json::json!({
                    "accounts": accounts,
                    "status": status,
                    "operation": payload,
                    "key": key
                })
        ));
    }

    // related account key case
    let (account_str, id_str) = key.rsplit_once(':')?;
    let account = serde_json::from_str::<Account>(account_str).ok()?;
    let id = serde_json::from_str::<AccountId32>(id_str).ok()?;
    let status = conn.get_status(key).ok()??;

    Some((
            id,
            serde_json::json!({
                "account": account,
                "status": status,
                "operation": payload,
                "key": key
            })
    ))
}
