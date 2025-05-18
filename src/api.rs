#![allow(dead_code)]

use anyhow::anyhow;
use anyhow::Result;
use chrono::{DateTime, Utc};
use diesel::dsl::any;
use diesel::RunQueryDsl;
use futures::channel::mpsc::{self, Sender};
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::Stream;
use futures::StreamExt;
use futures_util::SinkExt;
use once_cell::sync::OnceCell;
use redis::aio::ConnectionManager;
use redis::aio::PubSub;
use redis::AsyncCommands;
use redis::Msg;
use redis::RedisResult;
use redis::{self, Client as RedisClient};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::blake2_256;
use sp_core::Encode;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use subxt::events::EventDetails;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, span, Level};

use crate::db;
use crate::db::models::NewPgAddress;
use crate::db::models::PgAddress;
use diesel::QueryDsl;
use diesel::OptionalExtension;
use diesel::ExpressionMethods;
use crate::{
    adapter::pgp::PGPHelper,
    config::{RedisConfig, RegistrarConfig, GLOBAL_CONFIG},
    node::{
        self, filter_accounts,
        identity::events::{JudgementRequested, JudgementUnrequested},
        substrate::runtime_types::{
            pallet_identity::types::Registration,
            pallet_identity::types::{Data as IdentityData, Judgement},
            people_paseo_runtime::people::IdentityInfo,
        },
        Client as NodeClient,
    },
    token::{AuthToken, Token},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountVerification {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub network: String,
    /// AccountType: challengeInfo
    pub challenges: HashMap<String, ChallengeInfo>,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub name: String,
    pub done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl AccountVerification {
    pub fn new(network: String) -> Self {
        Self {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            network,
            challenges: HashMap::new(),
            completed: false,
        }
    }

    pub fn add_challenge(&mut self, account_type: &str, name: String, token: Option<String>) {
        self.challenges.insert(
            account_type.to_string(),
            ChallengeInfo {
                name,
                done: token.is_none(), // for now if no token provided, challenge is done
                token,
            },
        );
        self.updated_at = Utc::now();
        self.complete_all_challenges();
    }

    fn complete_all_challenges(&mut self) {
        self.completed = !self.challenges.is_empty() && self.challenges.values().all(|c| c.done);
    }

    pub fn mark_challenge_done(&mut self, account_type: &str) -> bool {
        if let Some(challenge) = self.challenges.get_mut(account_type) {
            challenge.done = true;
            challenge.token = None;
            self.updated_at = Utc::now();
            self.complete_all_challenges();
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationMode {
    Direct,
    Inbound,
    Outbound,
    Unsupported,
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

impl Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Account::Twitter(name) => write!(f, "twitter|{}", name),
            Account::Discord(name) => write!(f, "discord|{}", name),
            Account::Matrix(name) => write!(f, "matrix|{}", name),
            Account::Display(name) => write!(f, "display|{}", name),
            Account::Legal(name) => write!(f, "legal|{}", name),
            Account::Web(name) => write!(f, "web|{}", name),
            Account::Email(name) => write!(f, "email|{}", name),
            Account::Github(name) => write!(f, "github|{}", name),
            Account::PGPFingerprint(name) => write!(f, "pgp_fingerprint|{}", hex::encode(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy, Hash)]
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
            Account::Display(_) => ValidationMode::Direct,
            // Inbound: receive challenge/callback via websocket
            Account::Github(_) | Account::PGPFingerprint(_) => ValidationMode::Inbound,
            // Outbound: send challenge via websocket
            Account::Discord(_)
            | Account::Matrix(_)
            | Account::Email(_)
            | Account::Twitter(_)
            | Account::Web(_) => ValidationMode::Outbound,
            // Unsupported
            Account::Legal(_) => ValidationMode::Unsupported,
        }
    }

    pub fn should_skip_token(&self, is_done: bool) -> bool {
        is_done
            || self.determine() != ValidationMode::Outbound
                && !matches!(self, Account::PGPFingerprint(_))
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
            AccountType::Twitter => Self::Twitter(format!("@{}", value)),
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
        info!("Converting IdentityInfo into accounts: {:?}", value);
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

    pub fn into_hashmap<I>(accounts: I, done: bool) -> HashMap<Account, bool>
    where
        I: IntoIterator<Item = Account>,
    {
        accounts.into_iter().map(|acc| (acc, done)).collect()
    }
}

impl FromStr for Account {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let matrix_regex = Regex::new(r"@(?<name>[a-z0-9][a-z0-9.=/-]*):(?<domain>(?:[a-zA-Z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?)").unwrap();
        info!("Determining that account {s} is a valid format...");
        match matrix_regex.captures(s) {
            Some(account) => {
                info!("This {s} is a matrix account");
                let acc_name: &str = &account["name"];
                let domain: &str = &account["domain"];
                Ok(Self::Matrix(format!("@{}:{}", acc_name, domain)))
            }
            None => {
                let (account_type, value) = s
                    .split_once('|')
                    .ok_or_else(|| anyhow::anyhow!("Invalid account format, expected Type:Name"))?;
                info!("Account {s} is valid");
                info!("Account type: {account_type}");
                info!("Value: {value}");

                info!("Parsing the account type...");
                let account_type: AccountType = account_type.parse()?;
                info!("Account type {:?}", account_type);
                Ok(Self::from_type_and_value(
                    account_type,
                    value.trim().to_owned(),
                ))
            }
        }
    }
}

impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{}|{}", self.account_type(), self.inner());
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
    pub payload: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingSubscribeRequest {
    pub network: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingVerifyPGPRequest {
    pub network: String,
    pub signed_challenge: String,
    pub pubkey: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengedAccount {
    pub network: String,
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
    pub network: String,
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

// --------------------------------------
pub async fn spawn_node_listener() -> anyhow::Result<()> {
    let node_listener = NodeListener::new().await?;
    node_listener.listen().await
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
        network: &str,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        if !cfg.registrar.is_network_supported(network) {
            return Ok(serde_json::json!({
                "type": "error",
                "message": format!("Network {} not supported", network)
            }));
        }

        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        *subscriber = Some(request.payload.clone());
        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &request.payload).await?;

        let mut conn = RedisConnection::get_connection(&self.redis_cfg).await?;

        // 1) attempt to load existing verification state, if any
        let existing_verification = conn
            .get_verification_state(network, &request.payload)
            .await?;

        // 2) if none found, create a fresh AccountVerification
        let mut verification =
            existing_verification.unwrap_or_else(|| AccountVerification::new(network.to_string()));

        // get the accounts from the chain's identity info
        let accounts = filter_accounts(
            &registration.info,
            &request.payload,
            network_cfg.registrar_index,
            network,
        )
        .await?;

        // 3) for each discovered account, only create a token if we do not
        //    already have one stored. Otherwise, reuse the old token/challenge.
        for (account, is_done) in &accounts {
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

            // only add a new challenge if not already present.
            // if *is_done or it's a display_name, we set `token=None` so it's considered done.
            if !verification.challenges.contains_key(acc_type) {
                let token = if account.should_skip_token(*is_done) {
                    None
                } else {
                    Some(Token::generate().await.show())
                };
                verification.add_challenge(acc_type, name.clone(), token);
            }
        }

        // save new state
        conn.init_verification_state(network, &request.payload, &verification, &accounts)
            .await?;

        let address = &request.payload;

        db::upsert_address_and_accounts(
            network,
            address,
            &accounts,
        )?;

        // get hash and build state message
        let hash = self.hash_identity_info(&registration.info);

        // return state in json
        conn.build_account_state_message(network, &request.payload, Some(hash))
            .await
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
                let incoming: IncomingSubscribeRequest = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid SubscribeAccountState payload: {}", e))?;

                let internal_request = SubscribeAccountStateRequest {
                    _type: SubscribeAccountState::SubscribeAccountState,
                    payload: incoming.account,
                };

                self.handle_subscription_request(internal_request, &incoming.network, subscriber)
                    .await
            }
            "VerifyPGPKey" => {
                let incoming: IncomingVerifyPGPRequest = serde_json::from_value(message.payload)
                    .map_err(|e| anyhow!("Invalid SubscribeAccountState payload: {}", e))?;

                let network_str = incoming.network.clone();
                self.handle_pgp_verification_request(incoming, &network_str, subscriber)
                    .await
            }
            // TODO: Add endpoint for inputting verifications
            _ => Err(anyhow!(
                "Unsupported message type: {}",
                message.message_type
            )),
        }
    }

    pub async fn _handle_incoming(
        &mut self,
        message: Message,
        subscriber: &mut Option<AccountId32>,
    ) -> Result<serde_json::Value> {
        // 1) ensure the message is text
        let text = match message {
            Message::Text(t) => t,
            _ => {
                return Ok(json!({
                    "type": "error",
                    "message": "Unsupported message format"
                }))
            }
        };

        // 2) attempt to parse the JSON into a VersionedMessage
        let versioned_msg: VersionedMessage = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                return Ok(json!({
                    "type": "error",
                    "message": format!("Failed to parse message: {}", e)
                }))
            }
        };

        // 3) check the version
        if versioned_msg.version.as_str() != "1.0" {
            return Ok(json!({
                "type": "error",
                "message": format!("Unsupported version: {}", versioned_msg.version),
            }));
        }

        // 4) handle the v1 version
        match self.process_v1(versioned_msg, subscriber).await {
            Ok(response) => Ok(response),
            Err(e) => Ok(json!({
                "type": "error",
                "message": e.to_string()
            })),
        }
    }

    // TODO: check if Judgement is requested (JudgementRequested)
    /// checks if the registration request is well synchronized with the registrar node
    pub async fn check_node(
        id: AccountId32,
        accounts: Vec<Account>,
        network: &str,
    ) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &id).await?;

        info!("registration: {:#?}", registration);

        Self::is_complete(&registration, &accounts)?;
        // TODO: instead of using index 0 judgement search for our registrar judgement that its paid
        // now if there is more than 1 judgement from other registrars I think this breaks
        Self::has_paid_fee(registration.judgements.0)?;
        Self::validate_account_types(&accounts, network_cfg)?;

        Ok(())
    }

    fn validate_account_types(
        accounts: &[Account],
        network_cfg: &RegistrarConfig,
    ) -> anyhow::Result<()> {
        for account in accounts {
            let acc_type = account.account_type();
            let supported = network_cfg.fields.iter().any(|field| {
                AccountType::from_str(field)
                    .map(|f| f == acc_type)
                    .unwrap_or(false)
            });

            if !supported {
                return Err(anyhow!(
                    "Account type {} is not supported on this network",
                    acc_type,
                ));
            }
        }
        Ok(())
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
                Account::Email(email_acc) => {
                    (identity_data_tostring(&registration.info.email), email_acc)
                }
                Account::Discord(discord_acc) => (
                    identity_data_tostring(&registration.info.discord),
                    discord_acc,
                ),
                Account::Display(display_name) => (
                    identity_data_tostring(&registration.info.display),
                    display_name,
                ),
                // TODO: GITHUB
                Account::Matrix(matrix_acc) => (
                    identity_data_tostring(&registration.info.matrix),
                    matrix_acc,
                ),
                // TODO: PGP
                Account::Twitter(twit_acc) => {
                    (identity_data_tostring(&registration.info.twitter), twit_acc)
                }
                Account::Web(web_acc) => (identity_data_tostring(&registration.info.web), web_acc),
                Account::PGPFingerprint(fingerprint) => (
                    Some(hex::encode(
                        registration
                            .info
                            .pgp_fingerprint
                            .ok_or_else(|| anyhow!("Internal error"))?,
                    )),
                    &hex::encode(fingerprint),
                ),
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
        ws_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
        span: tracing::Span,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                Some(msg) = receiver.next() => {
                    if !self.handle_channel_message(&ws_write, msg, &span).await {
                        break;
                    }
                }

                Some(msg_result) = ws_read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            info!(parent: &span, "Received close frame");
                            break;
                        }
                        _ => {
                            if !self.handle_ws_message(&ws_write, msg_result, &mut subscriber, sender.clone(), &span).await {
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
                info!(parent: span, response_type = %resp_type, "Sending response");
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
                        if let Err(e) = cloned_self.spawn_redis_listener(sender, id, response).await
                        {
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
                if let Err(e) = cloned_self.spawn_redis_listener(sender, id, response).await {
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

    /// websocket listener
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
        response: serde_json::Value,
    ) -> anyhow::Result<()> {
        let redis_cfg = self.redis_cfg.clone();
        info!("Starting Redis listener task!");

        tokio::spawn(async move {
            let mut redis_conn = match RedisConnection::get_connection(&redis_cfg).await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to create Redis connection: {}", e);
                    return;
                }
            };

            let network = &response["payload"]["message"]["AccountState"]["network"];
            let channel = format!(
                "__keyspace@0__:{}|{}",
                account,
                network.as_str().unwrap_or_default(),
            );

            info!("Subscribing to channel: {}", channel);
            if let Err(e) = redis_conn.subscribe(&channel).await {
                error!("Unable to subscribe to {} because {:?}", channel, e);
                return;
            };

            // TODO: make this kill iteslf when an completed state is true, since we don't want
            // to listen for events forever!
            debug!("Starting message processing loop");
            let mut stream = redis_conn.pubsub_stream().await;
            while let Some(msg) = stream.next().await {
                debug!("Redis event received: {:?}", msg);

                // process message, continue on error
                let result = match RedisConnection::process_state_change(&redis_cfg, &msg).await {
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
                if (sender.send(obj).await).is_err() {
                    info!("WebSocket channel closed, stopping Redis listener");
                    break;
                }
            }
            debug!("Redis listener loop ended");
        });

        debug!("Redis listener task spawned");
        Ok(())
    }

    /// Handles PGP registration by checking signed challenge signature and challenge content
    async fn handle_pgp_verification_request(
        &self,
        request: IncomingVerifyPGPRequest,
        network: &str,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        // filter only supported networks
        if !cfg.registrar.is_network_supported(network) {
            return Err(anyhow!("Network {} not supported", network));
        }

        // get network configuration
        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        *subscriber = Some(request.account.clone());
        // get registration info on fron the blockchain node
        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &request.account).await?;

        let Some(registred_fingerprint) = registration.info.pgp_fingerprint else {
            return Err(anyhow!(
                "No fingerprint is registered on chain for {:?}",
                request.account
            ));
        };
        let account_id = request.account;

        // verify challenge
        PGPHelper::verify(
            request.signed_challenge.as_bytes(),
            registred_fingerprint,
            network,
            account_id,
        )
        .await
    }
}

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv() -> anyhow::Result<()> {
    let listener = Listener::new().await;
    let addr = listener.socket_addr;

    let tcp_listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to bind to address: {}", e);
            std::process::exit(1);
        });

    info!("WebSocket server listening on {}", addr);

    loop {
        match tcp_listener.accept().await {
            Ok((stream, addr)) => {
                info!("Incoming connection from {:?}...", addr);
                let mut clone = listener.clone();
                tokio::spawn(async move {
                    clone.handle_connection(stream.into_std().unwrap()).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
struct NodeListener {
    clients: HashMap<String, NodeClient>,
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
            let client = NodeClient::from_url(&network_cfg.endpoint)
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

        let registration = node::get_registration(client, who).await?;
        let accounts = Account::into_accounts(&registration.info);

        // validation
        Listener::check_node(who.clone(), accounts.clone(), network).await?;

        let mut conn = RedisConnection::get_connection(&self.redis_cfg).await?;
        conn.clear_all_related_to(network, who).await?;

        // filter accounts and create verification state
        let filtered_accounts = filter_accounts(
            &registration.info,
            who,
            network_cfg.registrar_index,
            network,
        )
        .await?;

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

            let token = if account.should_skip_token(*is_done) {
                None
            } else {
                Some(Token::generate().await.show())
            };
            verification.add_challenge(acc_type, name.clone(), token);
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

            let token = if account.should_skip_token(*is_done) {
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
        let mut conn = RedisConnection::get_connection(&self.redis_cfg).await?;
        conn.clear_all_related_to(network, who).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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

pub async fn spawn_redis_subscriber() -> anyhow::Result<()> {
    let redis_cfg = GLOBAL_CONFIG.get().unwrap().redis.clone();
    let span = span!(Level::INFO, "redis_subscriber");
    info!(parent: &span, "Starting Redis subscriber service");

    let mut redis_conn = RedisConnection::get_connection(&redis_cfg).await?;
    let mut stream = redis_conn.pubsub_stream().await;
    while let Some(msg) = stream.next().await {
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

// TODO: move this to another file?
static REDIS_CLIENT: OnceCell<Arc<RedisClient>> = OnceCell::new();

pub struct RedisConnection {
    conn: ConnectionManager,
    pubsub: PubSub,
}

impl RedisConnection {
    // Add a new async function to create a default instance
    pub async fn create_default() -> anyhow::Result<Self> {
        Self::get_connection(&GLOBAL_CONFIG.get().unwrap().redis).await
    }
}

impl Default for RedisConnection {
    fn default() -> Self {
        // Provide a meaningful error message rather than trying to use await
        panic!("RedisConnection cannot be created with Default::default(). Use RedisConnection::create_default().await instead")
    }
}

impl RedisConnection {
    pub fn initialize_pool(addr: &RedisConfig) -> anyhow::Result<()> {
        let span = span!(Level::INFO, "redis_connection", url = %addr.url()?);
        info!(parent: &span, "Initializing Redis client");

        let client = redis::Client::open(addr.url()?).map_err(|e| {
            error!(parent: &span, error = %e, "Failed to open Redis client");
            anyhow!("Cannot open Redis client: {}", e)
        })?;

        REDIS_CLIENT
            .set(Arc::new(client))
            .map_err(|_| anyhow!("Redis client already initialized"))?;

        info!(parent: &span, "Redis client initialized successfully");
        Ok(())
    }

    pub async fn get_connection(_config: &RedisConfig) -> anyhow::Result<Self> {
        let span = span!(Level::INFO, "redis_connection");

        let client = REDIS_CLIENT
            .get()
            .ok_or_else(|| anyhow!("Redis client not initialized"))?;

        let mut conn = client.get_connection_manager().await.map_err(|e| {
            error!(parent: &span, error = %e, "Failed to establish Redis connection");
            anyhow!("Cannot establish Redis connection: {}", e)
        })?;

        info!(parent: &span, "Enabling keyspace notifications");
        Self::enable_keyspace_notifications(&mut conn).await?;
        let pubsub = client.get_async_pubsub().await?;

        info!(parent: &span, "Redis connection successfully established");
        Ok(Self { conn, pubsub })
    }

    pub async fn subscribe(&mut self, channel: &str) -> RedisResult<()> {
        self.pubsub.psubscribe(channel).await
    }

    pub async fn pubsub_stream(&mut self) -> impl Stream<Item = Msg> + '_ {
        self.pubsub.on_message()
    }

    async fn enable_keyspace_notifications(conn: &mut ConnectionManager) -> anyhow::Result<()> {
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
    pub async fn search(&mut self, pattern: &str) -> anyhow::Result<Vec<String>> {
        // self.conn.s
        Ok(self
            .conn
            .scan_match::<&str, String>(pattern)
            .await?
            .collect::<Vec<String>>()
            .await)
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

    async fn clear_all_related_to(
        &mut self,
        network: &str,
        who: &AccountId32,
    ) -> anyhow::Result<()> {
        let mut pipe = redis::pipe();
        pipe.cmd("DEL").arg(format!("{}|{}", who, network));

        let accounts = self.search(&format!("*|{}|{}", network, who)).await?;
        for account in accounts {
            pipe.cmd("DEL").arg(account);
        }

        pipe.exec_async(&mut self.conn).await?;
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
        for account in accounts.keys() {
            let key = format!("{}|{}|{}", account, network, account_id);
            let pipe = pipe.cmd("SET").arg(&key);
            if let Some(challenge_info) = state.challenges.get(&account.account_type().to_string())
            {
                pipe.arg(&serde_json::to_string(&challenge_info)?);
            }
        }
        pipe.exec_async(&mut self.conn).await?;
        Ok(())
    }

    pub async fn save_state(
        &mut self,
        network: &str,
        account_id: &AccountId32,
        state: &AccountVerification,
    ) -> anyhow::Result<()> {
        let key = format!("{}|{}", account_id, network);
        let value = serde_json::to_string(&state)?;

        redis::pipe()
            .cmd("SET")
            .arg(&key)
            .arg(value)
            .exec_async(&mut self.conn)
            .await?;

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

        for (acc_type, info) in state.challenges.iter() {
            let account_type = AccountType::from_str(acc_type)?;
            let acc_key = Account::from_type_and_value(account_type, info.name.clone());
            let key = format!("{}|{}|{}", acc_key, network, account_id);
            pipe.cmd("SET")
                .arg(&key)
                .arg(&serde_json::to_string(&info)?);
        }

        pipe.exec_async(&mut self.conn).await?;
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
        let key = format!("{}|{}", account_id, network);
        info!("key: {}", key);
        let value: Option<String> = self.conn.get(&key).await?;

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

    async fn build_account_state_message(
        &mut self,
        network: &str,
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

    pub async fn process_state_change(
        redis_cfg: &RedisConfig,
        msg: &redis::Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection(redis_cfg).await?;
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
        let (account_id, network) = match key.split_once('|') {
            Some(parts) => parts,
            None => return Ok(None),
        };

        let id = match AccountId32::from_str(account_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        let account_state = conn.build_account_state_message(network, &id, None).await?;

        Ok(Some((id, account_state)))
    }
}
