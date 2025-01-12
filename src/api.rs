#![allow(dead_code)]

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use futures::channel::mpsc::{self, Sender};
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::StreamExt;
use futures_util::SinkExt;
use redis::{self, RedisError};
use redis::{Client as RedisClient, Commands};
use serde::{Deserialize, Serialize};
use sp_core::blake2_256;
use sp_core::Encode;
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use subxt::events::EventDetails;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, span, warn, Instrument, Level};

use crate::config::GLOBAL_CONFIG;

use crate::{
    config::RedisConfig,
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
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub enum VerifStatus {
    Done,
    Pending,
}

impl VerifStatus {
    pub async fn set_done(&mut self) -> anyhow::Result<()> {
        *self = Self::Done;
        anyhow::Result::Ok(())
    }
}

impl fmt::Display for VerifStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Done => write!(f, "Done"),
            Self::Pending => write!(f, "Pending"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationState {
    pub status: VerifStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub media_types: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAccount {
    pub name: String,
    pub status: VerifStatus,
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationMode {
    Direct,
    Inbound,
    Outbound,
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
    PGPFingerprint([u8; 20]),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum AccountType {
    Discord,
    #[serde(rename = "display_name")]
    Display,
    Email,
    Matrix,
    Twitter,
    Github,
    Legal,
    Web,
    PGPFingerprint,
}

impl FromStr for AccountType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "discord" => Ok(Self::Discord),
            "display_name" => Ok(Self::Display),
            "email" => Ok(Self::Email),
            "matrix" => Ok(Self::Matrix),
            "twitter" => Ok(Self::Twitter),
            "github" => Ok(Self::Github),
            "legal" => Ok(Self::Legal),
            "web" => Ok(Self::Web),
            "pgp_fingerprint" => Ok(Self::PGPFingerprint),
            _ => Err(anyhow::anyhow!("Invalid account type: {}", s)),
        }
    }
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discord => write!(f, "discord"),
            Self::Display => write!(f, "display_name"),
            Self::Email => write!(f, "email"),
            Self::Matrix => write!(f, "matrix"),
            Self::Twitter => write!(f, "twitter"),
            Self::Github => write!(f, "github"),
            Self::Legal => write!(f, "legal"),
            Self::Web => write!(f, "web"),
            Self::PGPFingerprint => write!(f, "pgp_fingerprint"),
        }
    }
}

impl Account {
    pub fn determine(&self) -> ValidationMode {
        match self {
            // Direct: verified directly without user action
            Account::Display(_) | Account::Web(_) => ValidationMode::Direct,
            // Inbound: receive challenge via websocket
            Account::Email(_) | Account::PGPFingerprint(_) => ValidationMode::Inbound,
            // Outbound: send challenge via websocket
            Account::Discord(_)
            | Account::Github(_)
            | Account::Legal(_)
            | Account::Matrix(_)
            | Account::Twitter(_) => ValidationMode::Outbound,
        }
    }

    pub fn account_type(&self) -> AccountType {
        match self {
            Self::Discord(_) => AccountType::Discord,
            Self::Display(_) => AccountType::Display,
            Self::Email(_) => AccountType::Email,
            Self::Matrix(_) => AccountType::Matrix,
            Self::Twitter(_) => AccountType::Twitter,
            Self::Github(_) => AccountType::Github,
            Self::Legal(_) => AccountType::Legal,
            Self::Web(_) => AccountType::Web,
            Self::PGPFingerprint(_) => AccountType::PGPFingerprint,
        }
    }

    pub fn inner(&self) -> String {
        match self {
            Self::Twitter(v)
            | Self::Discord(v)
            | Self::Matrix(v)
            | Self::Display(v)
            | Self::Email(v)
            | Self::Legal(v)
            | Self::Github(v)
            | Self::Web(v) => v.to_owned(),
            Self::PGPFingerprint(v) => hex::encode(v),
        }
    }

    pub fn from_type_and_value(account_type: AccountType, value: String) -> Self {
        match account_type {
            AccountType::Discord => Self::Discord(value),
            AccountType::Display => Self::Display(value),
            AccountType::Email => Self::Email(value),
            AccountType::Matrix => Self::Matrix(value),
            AccountType::Twitter => Self::Twitter(value),
            AccountType::Github => Self::Github(value),
            AccountType::Legal => Self::Legal(value),
            AccountType::Web => Self::Web(value),
            AccountType::PGPFingerprint => {
                if let Ok(bytes) = hex::decode(&value) {
                    if bytes.len() == 20 {
                        let mut fingerprint = [0u8; 20];
                        fingerprint.copy_from_slice(&bytes);
                        Self::PGPFingerprint(fingerprint)
                    } else {
                        Self::PGPFingerprint([0u8; 20])
                    }
                } else {
                    Self::PGPFingerprint([0u8; 20])
                }
            }
        }
    }

    pub fn into_accounts(value: &IdentityInfo) -> Vec<Account> {
        let mut accounts = Vec::new();

        let mut add_if_some = |data: &IdentityData, constructor: fn(String) -> Account| {
            if let Some(value) = identity_data_tostring(data) {
                accounts.push(constructor(value));
            }
        };

        add_if_some(&value.discord, Account::Discord);
        add_if_some(&value.twitter, Account::Twitter);
        add_if_some(&value.matrix, Account::Matrix);
        add_if_some(&value.email, Account::Email);
        add_if_some(&value.display, Account::Display);
        add_if_some(&value.github, Account::Github);
        add_if_some(&value.legal, Account::Legal);
        add_if_some(&value.web, Account::Web);

        if let Some(fingerprint) = value.pgp_fingerprint {
            accounts.push(Account::PGPFingerprint(fingerprint));
        }

        accounts
    }

    pub fn into_hashmap<I>(accounts: I, status: VerifStatus) -> HashMap<Account, VerifStatus>
    where
        I: IntoIterator<Item = Account>,
    {
        accounts
            .into_iter()
            .map(|acc| (acc, status.clone()))
            .collect()
    }
}

impl FromStr for Account {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (account_type, value) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid account format, expected Type:Name"))?;

        let account_type: AccountType = account_type.parse()?;
        Ok(Self::from_type_and_value(
            account_type,
            value.trim().to_owned(),
        ))
    }
}

impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{}:{}", self.account_type(), self.inner());
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
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
    JsonResult(JsonResultPayload),
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
pub struct JsonResultPayload {
    #[serde(rename = "type")]
    response_type: String,
    message: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NotifyAccountState {
    NotifyAccountState,
}
// --------------------------------------
pub async fn spawn_node_listener() -> anyhow::Result<()> {
    NodeListener::new().await?.listen().await
}

/// Converts the inner of [IdentityData] to a [String]
pub fn identity_data_tostring(data: &IdentityData) -> Option<String> {
    let result = match data {
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
    };
    debug!("Data: {:?}", result);

    result
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
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
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

        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let client = NodeClient::from_url(&cfg.registrar.endpoint).await?;
        let registration = node::get_registration(&client, &request.payload).await?;

        let mut conn = RedisConnection::create_conn(redis_cfg)?;

        conn.clear_all_related_to(&request.payload).await?;

        let accounts = filter_accounts(
            &registration.info,
            &request.payload,
            cfg.registrar.registrar_index,
            &cfg.registrar.endpoint,
        )
        .await?;

        for (account, status) in &accounts {
            if !matches!(status, VerifStatus::Pending) {
                continue;
            }

            match account {
                Account::Display(name) => {
                    info!("Display account found: {}, marking as Done", name);
                    conn.save_account(&request.payload, account, None, VerifStatus::Done)
                        .await?;
                }
                _ => {
                    conn.save_account(
                        &request.payload,
                        account,
                        Some(Token::generate().await),
                        VerifStatus::Pending,
                    )
                    .await?;
                }
            }
        }

        conn.save_owner(&request.payload, &accounts).await?;

        let verification_fields = conn.extract_info(&request.payload)?;
        let hash = self.hash_identity_info(&registration.info);
        let pending_challenges = conn.get_challenges(&request.payload)?;

        Ok(serde_json::json!({
            "type": "JsonResult",
            "payload": {
                "type": "ok",
                "message": {
                    "AccountState": {
                        "account": request.payload.to_string(),
                        "hashed_info": hash,
                        "verification_state": {
                            "fields": verification_fields
                        },
                        "pending_challenges": pending_challenges
                    }
                }
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
                let payload = message
                    .payload
                    .as_str()
                    .ok_or_else(|| anyhow!("Payload must be a string"))?;
                let account_id = AccountId32::from_str(payload)
                    .map_err(|e| anyhow!("Invalid account ID: {}", e))?;

                let req = SubscribeAccountStateRequest {
                    _type: SubscribeAccountState::SubscribeAccountState,
                    payload: account_id,
                };

                self.handle_subscription_request(req, subscriber).await
            }
            "VerifyIdentity" => {
                let verify_request: ChallengedAccount = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid VerifyIdentity payload: {}", e))?;

                let internal_request = VerifyIdentityRequest {
                    _type: "VerifyIdentity".to_string(),
                    payload: verify_request,
                };

                self.handle_identity_verification_request(internal_request)
                    .await
            }
            _ => Err(anyhow!(
                "Unsupported message type: {}",
                message.message_type
            )),
        }
    }

    async fn _handle_incoming(
        &mut self,
        message: tokio_tungstenite::tungstenite::Message,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        if let Message::Text(text) = message {
            match serde_json::from_str::<VersionedMessage>(&text) {
                Ok(versioned_msg) => match versioned_msg.version.as_str() {
                    "1.0" => match self.process_v1(versioned_msg, subscriber).await {
                        Ok(response) => Ok(response),
                        Err(e) => Ok(serde_json::json!({
                            "type": "error",
                            "message": e.to_string()
                        })),
                    },
                    _ => Ok(serde_json::json!({
                        "type": "error",
                        "message": format!("Unsupported version: {}", versioned_msg.version)
                    })),
                },
                Err(e) => Ok(serde_json::json!({
                    "type": "error",
                    "message": format!("Failed to parse message: {}", e)
                })),
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
                Account::Twitter(twit_acc) => {
                    (identity_data_tostring(&registration.info.twitter), twit_acc)
                }
                Account::Email(email_acc) => {
                    (identity_data_tostring(&registration.info.email), email_acc)
                }
                _ => todo!(),
            };

            let stored_acc = stored_acc.ok_or_else(|| {
                anyhow!(
                    "{} acc {} not in identity obj",
                    acc.account_type(),
                    expected_acc
                )
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
        let challenge_identifier =
            format!("{}:{:?}", request.payload.account, request.payload.field);
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
            None => Ok(serde_json::json!({
                "type": "error",
                "reason": format!("could not find challenge for {}", challenge_identifier),
            })),
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

    async fn send_message(
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: String,
    ) -> Result<(), anyhow::Error> {
        debug!("Attempting to send message: {}", msg);
        let mut guard = write.lock().await;
        let result = guard.send(Message::Text(msg.into())).await;
        debug!("Message send result: {:?}", result);
        result.map_err(|e| e.into())
    }

    async fn process_websocket(
        &mut self,
        write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut read: SplitStream<WebSocketStream<TcpStream>>,
        span: tracing::Span,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                Some(msg) = receiver.next() => {
                    if !self.handle_channel_message(&write, msg, &span).await {
                        break;
                    }
                }

                Some(msg_result) = read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            info!(parent: &span, "Received close frame");
                            break;
                        }
                        _ => {
                            if !self.handle_ws_message(&write, msg_result, &mut subscriber, sender.clone(), &span).await {
                                break;
                            }
                        }
                    }
                }

                else => {
                    info!(parent: &span, "WebSocket or channel stream ended");
                    break;
                }
            }
        }

        // Cleanup
        if let Some(id) = subscriber {
            info!(parent: &span, subscriber_id = %id, "Cleaning up subscriber");
        }
        info!(parent: &span, "WebSocket connection closed");
    }

    async fn handle_channel_message(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: serde_json::Value,
        span: &tracing::Span,
    ) -> bool {
        let resp_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                debug!(parent: span, response_type = %resp_type, "Sending response");
                match Self::send_message(write, serialized).await {
                    Ok(_) => true,
                    Err(e) => {
                        error!(parent: span, error = %e, "Failed to send message");
                        false
                    }
                }
            }
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize response");
                true
            }
        }
    }

    async fn handle_ws_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg_result: Result<Message, tokio_tungstenite::tungstenite::Error>,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        match msg_result {
            Ok(Message::Text(bytes)) => {
                // Convert Utf8Bytes to string using to_string()
                let text = bytes.to_string();
                self.handle_text_message(write, text, subscriber, sender, span)
                    .await
            }
            Ok(Message::Close(_)) => {
                info!(parent: span, "Received close frame");
                false
            }
            Ok(_) => {
                debug!(parent: span, "Received non-text message");
                true
            }
            Err(e) => {
                error!(parent: span, error = %e, "WebSocket error");
                false
            }
        }
    }

    async fn handle_text_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        text: String,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        let parsed: VersionedMessage = match serde_json::from_str(&text) {
            Ok(msg) => msg,
            Err(_) => {
                error!(parent: span, "Failed to parse WebSocket message");
                return true;
            }
        };

        info!(
            parent: span,
            message_version = %parsed.version,
            message_type = %parsed.message_type,
            "Received WebSocket message"
        );

        match self
            ._handle_incoming(Message::Text(text.into()), subscriber)
            .await
        {
            Ok(response) => {
                let serialized = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(parent: span, error = %e, "Failed to serialize response");
                        return true;
                    }
                };

                if let Err(e) = Self::send_message(write, serialized).await {
                    error!(parent: span, error = %e, "Failed to send response");
                    return false;
                }

                if let Some(id) = subscriber.take() {
                    info!(parent: span, subscriber_id = %id, "New subscriber registered");
                    let mut cloned_self = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = cloned_self.spawn_redis_listener(sender, id).await {
                            error!(error = %e, "Redis listener error");
                        }
                    });
                }
                true
            }
            Err(e) => self.handle_error_response(write, e, span).await,
        }
    }

    async fn handle_successful_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        response: serde_json::Value,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
        span: &tracing::Span,
    ) -> bool {
        debug!("Handling successful response: {:?}", response);

        let serialized = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize response");
                return true;
            }
        };

        let resp_type = response
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        debug!(parent: span, response_type = %resp_type, "Sending response");

        if let Err(e) = Self::send_message(write, serialized).await {
            error!(parent: span, error = %e, "Failed to send response");
            return false;
        }

        if let Some(id) = subscriber.take() {
            info!(parent: span, subscriber_id = %id, "New subscriber registered");
            let mut cloned_self = self.clone();
            tokio::spawn(async move {
                if let Err(e) = cloned_self.spawn_redis_listener(sender, id).await {
                    error!(error = %e, "Redis listener error");
                }
            });
        }

        true
    }

    async fn handle_error_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        error: anyhow::Error,
        span: &tracing::Span,
    ) -> bool {
        error!(parent: span, error = %error, "Error handling message");

        let error_response = serde_json::json!({
            "version": "1.0",
            "error": error.to_string()
        });

        match serde_json::to_string(&error_response) {
            Ok(serialized) => match Self::send_message(write, serialized).await {
                Ok(_) => true,
                Err(e) => {
                    error!(parent: span, error = %e, "Failed to send error response");
                    false
                }
            },
            Err(e) => {
                error!(parent: span, error = %e, "Failed to serialize error response");
                true
            }
        }
    }

    /// Handles incoming websocket connection
    pub async fn handle_connection(&mut self, stream: std::net::TcpStream) {
        let peer_addr = stream
            .peer_addr()
            .map_or("unknown".to_string(), |addr| addr.to_string());
        let conn_span = span!(Level::INFO, "ws_connection", peer_addr = %peer_addr);

        info!(parent: &conn_span, "New WebSocket connection attempt");

        let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
            Ok(stream) => {
                debug!(parent: &conn_span, "Successfully converted to tokio TcpStream");
                stream
            }
            Err(e) => {
                error!(parent: &conn_span, error = %e, "Failed to convert to tokio TcpStream");
                return;
            }
        };

        let ws_stream = match tokio_tungstenite::accept_async(tokio_stream).await {
            Ok(stream) => {
                info!(parent: &conn_span, "WebSocket handshake successful");
                stream
            }
            Err(e) => {
                error!(parent: &conn_span, error = %e, "WebSocket handshake failed");
                return;
            }
        };

        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        info!(parent: &conn_span, "Starting WebSocket message processing");
        self.process_websocket(write, read, conn_span).await;
    }

    // websocket listener
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
            let mut redis_conn = match RedisConnection::create_conn(&redis_cfg) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to create Redis connection: {}", e);
                    return;
                }
            };

            let mut pubsub = redis_conn.as_pubsub();
            let channel = format!(
                "__keyspace@0__:{}",
                serde_json::to_string(&account).unwrap()
            );

            info!("Subscribing to channel: {}", channel);
            if let Err(e) = pubsub.subscribe(&channel) {
                error!("Failed to subscribe to channel: {}", e);
                return;
            }

            debug!("Starting message processing loop");
            loop {
                // get message or break on error
                let msg = match pubsub.get_message() {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Error getting Redis message: {}", e);
                        break;
                    }
                };

                debug!("Redis event received: {:?}", msg);

                // process message, continue on error
                let result = match process_redis_account_change(&redis_cfg, &msg).await {
                    Ok(result) => result,
                    Err(e) => {
                        info!("Failed to process Redis message {:?}: {:#?}", msg, e);
                        continue;
                    }
                };

                // extract object if it exists, continue if none
                let (_, obj) = match result {
                    Some(data) => data,
                    None => continue,
                };

                // send message, break if channel closed
                if let Err(_) = sender.send(obj).await {
                    info!("WebSocket channel closed, stopping Redis listener");
                    break;
                }
            }
            debug!("Redis listener loop ended");
        });

        debug!("Redis listener task spawned");
        Ok(())
    }
}

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv() -> ! {
    let mut listener = Listener::new().await;
    listener.listen().await
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
    pub async fn new() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        Ok(Self {
            client: NodeClient::from_url(&cfg.registrar.endpoint).await?,
            redis_cfg: cfg.redis.clone(),
            reg_index: cfg.registrar.registrar_index.clone(),
            endpoint: cfg.registrar.endpoint.clone(),
        })
    }

    pub async fn handle_node_events(&mut self, event: EventDetails<SubstrateConfig>) {
        let span = span!(Level::INFO, "node_event");

        if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
            info!(
                parent: &span,
                requester = %req.who,
                "Judgement requested"
            );

            match self.handle_registration(&req.who).await {
                Ok(_) => info!(
                    parent: &span,
                    requester = %req.who,
                    "Successfully processed registration request"
                ),
                Err(e) => error!(
                    parent: &span,
                    error = %e,
                    requester = %req.who,
                    "Failed to process registration request"
                ),
            }
        } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
            info!(
                parent: &span,
                requester = %req.who,
                "Judgement unrequested"
            );

            match self.cancel_registration(&req.who).await {
                Ok(_) => info!(
                    parent: &span,
                    requester = %req.who,
                    "Successfully cancelled registration"
                ),
                Err(e) => error!(
                    parent: &span,
                    error = %e,
                    requester = %req.who,
                    "Failed to cancel registration"
                ),
            }
        }
    }

    /// Listens for incoming events on the substrate node, in particular
    /// the `requestJudgement` event
    pub async fn listen(self) -> anyhow::Result<()> {
        let span = span!(Level::INFO, "node_listener");
        info!(parent: &span, "Starting node listener");

        let mut block_stream = self.client.blocks().subscribe_finalized().await?;
        info!(parent: &span, "Successfully subscribed to finalized blocks");

        tokio::spawn(async move {
            while let Some(item) = block_stream.next().await {
                match item {
                    Ok(block) => {
                        debug!(
                            parent: &span,
                            block_number = ?block.number(),
                            "Processing block"
                        );

                        if let Ok(events) = block.events().await {
                            let mut self_clone = self.clone();
                            self_clone.process_block_events(&span, events).await;
                        }
                    }
                    Err(e) => error!(
                        parent: &span,
                        error = %e,
                        "Failed to process block"
                    ),
                }
            }
            warn!(parent: &span, "Block stream ended");
        });

        Ok(())
    }

    /// process block events we listen
    async fn process_block_events(
        &mut self,
        span: &tracing::Span,
        events: subxt::events::Events<SubstrateConfig>,
    ) {
        for event_result in events.iter() {
            if let Ok(event) = event_result {
                if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
                    info!(
                        parent: span,
                        requester = %req.who,
                        "Judgement requested"
                    );

                    match self.handle_registration(&req.who).await {
                        Ok(_) => info!(
                            parent: span,
                            requester = %req.who,
                            "Successfully processed registration request"
                        ),
                        Err(e) => error!(
                            parent: span,
                            error = %e,
                            requester = %req.who,
                            "Failed to process registration request"
                        ),
                    }
                } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
                    info!(
                        parent: span,
                        requester = %req.who,
                        "Judgement unrequested"
                    );

                    match self.cancel_registration(&req.who).await {
                        Ok(_) => info!(
                            parent: span,
                            requester = %req.who,
                            "Successfully cancelled registration"
                        ),
                        Err(e) => error!(
                            parent: span,
                            error = %e,
                            requester = %req.who,
                            "Failed to cancel registration"
                        ),
                    }
                }
            }
        }
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

                let cfg = GLOBAL_CONFIG
                    .get()
                    .expect("GLOBAL_CONFIG is not initialized");
                let accounts = filter_accounts(
                    &reg.info,
                    who,
                    cfg.registrar.registrar_index,
                    &cfg.registrar.endpoint,
                )
                .await?;

                // TODO: make all commands chained together and then executed
                // all at once!
                conn.save_owner(who, &accounts).await?;
                conn.save_accounts(who, accounts).await?;

                Ok(())
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
    pub display_name: bool,
    pub github: bool,
    pub legal: bool,
    pub web: bool,
    pub pgp_fingerprint: bool,
}

impl Default for VerificationFields {
    fn default() -> Self {
        Self {
            matrix: false,
            display_name: false,
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
    //   network: String, // relaychain e.g. "polkadot", "kusama"
}

// TODO: move this to another file?
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
        let related_keys = self.search(format!("*:{}", account_id.to_string()))?;
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

        println!("Wallet ID string: {}", wallet_id_str);

        let pending_accounts = self.get_accounts_from_status(wallet_id, VerifStatus::Pending);
        println!("Pending accounts: {:?}", pending_accounts);

        Ok(pending_accounts
            .into_iter()
            .filter_map(|account| {
                let info = format!(
                    "{}:{}",
                    format!("{}:{}", account.account_type(), account.inner()),
                    wallet_id.to_string()
                );
                println!("Checking challenge for info key: {}", info);

                match self.get_challenge_token_from_account_info(&info) {
                    Ok(Some(token)) => {
                        println!("Found challenge token: {}", token.show());
                        Some(vec![account.account_type().to_string(), token.show()])
                    }
                    Ok(None) => {
                        println!("No challenge token found for account");
                        None
                    }
                    Err(e) => {
                        println!("Error retrieving challenge token: {:?}", e);
                        None
                    }
                }
            })
            .collect())
    }

    /// constructing [VerificationFields] object from the registration status of all the accounts
    /// under `wallet_id`
    pub fn extract_info(&mut self, wallet_id: &AccountId32) -> anyhow::Result<VerificationFields> {
        let accounts: String = self.conn.hget(wallet_id.to_string(), "accounts")?;
        let accounts: HashMap<Account, VerifStatus> = serde_json::from_str(&accounts)?;
        let mut verif_state = VerificationFields::default();

        for (account, acc_state) in accounts {
            if acc_state == VerifStatus::Done {
                match account {
                    Account::Discord(_) => verif_state.discord = true,
                    Account::Display(_) => verif_state.display_name = true,
                    Account::Email(_) => verif_state.email = true,
                    Account::Twitter(_) => verif_state.twitter = true,
                    Account::Matrix(_) => verif_state.matrix = true,
                    Account::Github(_) => verif_state.github = true,
                    Account::Legal(_) => verif_state.legal = true,
                    Account::Web(_) => verif_state.web = true,
                    Account::PGPFingerprint(_) => verif_state.pgp_fingerprint = true,
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
        // helper closure to create account key
        let make_info = |account: &Account| -> anyhow::Result<String> {
            Ok(format!(
                "{}:{}",
                format!("{}:{}", account.account_type(), account.inner()),
                wallet_id.to_string()
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
                    | (AccountType::Github, Account::Github(_))
                    | (AccountType::Legal, Account::Legal(_))
                    | (AccountType::Web, Account::Web(_))
                    | (AccountType::PGPFingerprint, Account::PGPFingerprint(_))
            )
        });

        // if we found a matching account, get its token
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
            status.to_string(),
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
            wallet_id.to_string(),
            "status",
            VerifStatus::Done.to_string(),
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
    /// This DOES NOT query anything from the people chain,
    /// rather it gets its info from locally on the `redis` server
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
    /// This DOES NOT query anything from the peoples network, rather it gets its info from the
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

        let accounts = self.search(format!("*:{}", who))?;
        for account in accounts {
            redis::pipe().cmd("DEL").arg(account).exec(&mut self.conn)?;
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

    /// Checks if the status of a given account is consistent between the Redis hashset
    /// and the local metadata stored under the associated wallet ID.
    ///
    /// Returns:
    /// - `Ok(Some(true))`: If the statuses match.
    /// - `Ok(Some(false))`: If the statuses do not match.
    /// - `Ok(None)`: If the account or wallet ID is not found.
    pub fn is_consistent(&mut self, account: &str) -> anyhow::Result<Option<bool>> {
        if let Some((acc, wallet_id)) = account.rsplit_once(':') {
            let wallet_id = serde_json::from_str(wallet_id)?;
            let acc = serde_json::from_str::<Account>(acc)?;

            if let Some(lstatus) = self.get_accounts(&wallet_id)?.unwrap_or_default().get(&acc) {
                let rstatus: String = self.conn.hget(account, "status")?;
                let rstatus: VerifStatus = serde_json::from_str(&rstatus)?;

                return Ok(Some(rstatus == *lstatus));
            }
        }
        Ok(None)
    }

    async fn save_accounts(
        &mut self,
        who: &AccountId32,
        accounts: HashMap<Account, VerifStatus>,
    ) -> anyhow::Result<()> {
        for (account, status) in accounts {
            match status {
                VerifStatus::Done => self.save_account(who, &account, None, status).await?,
                VerifStatus::Pending => {
                    self.save_account(who, &account, Some(Token::generate().await), status)
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn save_account(
        &mut self,
        who: &AccountId32,
        account: &Account,
        token: Option<Token>,
        status: VerifStatus,
    ) -> anyhow::Result<(), RedisError> {
        let span = span!(
            Level::DEBUG,
            "save_account",
            account_id = %who,
            account_type = %account.account_type(),
            status = ?status
        );

        async move {
            info!("Saving account information to Redis");
            debug!(token = ?token, "Challenge token details");

            let key = format!("{}:{}", account.account_type(), account.inner());

            debug!("Generated Redis key: {}", key);

            let mut cmd = redis::cmd("HSET");
            cmd.arg(&key)
                .arg("status")
                .arg(status.to_string())
                .arg("wallet_id")
                .arg(who.to_string());

            let validation_mode = account.determine();

            if matches!(
                validation_mode,
                ValidationMode::Inbound | ValidationMode::Outbound
            ) {
                if let Some(token_value) = token {
                    info!("Token provided for account: {}", token_value.show());
                    cmd.arg("token").arg(token_value.show());
                } else {
                    info!("No token provided for an Inbound/Outbound account.");
                }
            }

            let result = cmd.exec(&mut self.conn);

            match &result {
                Ok(_) => {
                    debug!("Saved account information for key: {}", key);
                }
                Err(e) => {
                    error!(
                        "Failed to save account information for key: {}, Error: {:?}",
                        key, e
                    );
                }
            }

            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn save_owner(
        &mut self,
        who: &AccountId32,
        accounts: &HashMap<Account, VerifStatus>,
    ) -> anyhow::Result<(), RedisError> {
        redis::pipe()
            .cmd("HSET")
            .arg(who.to_string())
            .arg("accounts")
            .arg(serde_json::to_string(&accounts)?)
            .arg("status")
            .arg(VerifStatus::Pending.to_string())
            .exec(&mut self.conn)
    }
}

async fn process_redis_account_change(
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

    if !matches!(payload.as_str(), "hset" | "hdel" | "del") {
        info!("Ignoring Redis operation: {}", payload);

        return Ok(None);
    }

    let key = channel.strip_prefix("__keyspace@0__:").unwrap_or_default();

    // main account key case
    //    if let Ok(id) = serde_json::from_str::<AccountId32>(key) {
    if let Ok(id) = AccountId32::from_str(key) {
        let accounts = conn.get_accounts(&id)?.unwrap_or_default();
        let status_str: String = conn.conn.hget(key, "status")?;
        let status = serde_json::from_str::<VerifStatus>(&status_str)?;

        return Ok(Some((
            id,
            serde_json::json!({
                "accounts": accounts,
                "status": status,
                "operation": payload,
                "key": key
            }),
        )));
    }

    // related account key case
    if let Some((account_str, id_str)) = key.rsplit_once(':') {
        let account = serde_json::from_str::<Account>(account_str)?;
        let id = serde_json::from_str::<AccountId32>(id_str)?;
        let status = conn
            .get_status(key)?
            .ok_or_else(|| anyhow::anyhow!("Couldn't retrieve status for key: {}", key))?;

        return Ok(Some((
            id,
            serde_json::json!({
                "account": account,
                "status": status,
                "operation": payload,
                "key": key
            }),
        )));
    }

    Ok(None)
}
