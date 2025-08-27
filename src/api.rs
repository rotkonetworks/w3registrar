#![allow(dead_code)]
// NOTE: Logging Hygiene
// 1) Log only base operations (things that are not done by ur own code) for example
// if foo calls bar, and both are written by you, log what happen in bar but not the returned
// value/state than log that returned value in foo so we don't log the same thing twice
// 2) Log returned values after they are returned, if possible, by other complex operations (code u've written)
// 3) Start the log by an Uppercase letter
// 4) Use the instrument macro whenever is possible
// 4.5) Use skip()/skip_all for sensitive info (passwords)
// 5) Log error as they happen and pass then upward if feasible
// 6) Refrain from using .unwrap and use anyhow::Result whenever is possible/feasible
//
// TODO: clear data related to registration if it fails at some point
// TODO: reduce the usage [Clone] :)
use crate::redis::RedisConnection;
use anyhow::anyhow;
use anyhow::Result;
use axum::extract::Query;
use axum::{routing::get, Router};
use chrono::{DateTime, Utc};
use futures::channel::mpsc::{self, Sender};
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::StreamExt;
use futures_util::SinkExt;
use once_cell::sync::OnceCell;
use postgres_types::FromSql;
use postgres_types::ToSql;
use redis::Msg;
use redis::{self, Client as RedisClient};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::blake2_256;
use sp_core::Encode;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use subxt::events::EventDetails;
use subxt::utils::AccountId32;
use subxt::SubstrateConfig;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::info_span;
use tracing::instrument;
use tracing::Span;
use tracing::{debug, error, info};
use tungstenite::Error;

use crate::{
    adapter::{
        github::{Github, GithubRedirectStepTwoParams},
        pgp::PGPHelper,
        Adapter,
    },
    config::{RedisConfig, RegistrarConfig, GLOBAL_CONFIG},
    indexer::Indexer,
    node::{
        self, filter_accounts, get_judgement,
        identity::events::{JudgementGiven, JudgementRequested, JudgementUnrequested},
        substrate::runtime_types::{
            pallet_identity::types::Registration,
            pallet_identity::types::{Data as IdentityData, Judgement},
            people_paseo_runtime::people::IdentityInfo,
        },
        Block, Client as NodeClient,
    },
    postgres::{
        DisplayedInfo, PostgresConnection, RegistrationCondition, RegistrationDisplayed,
        RegistrationQuery, RegistrationRecord, SearchInfo, TimelineQuery,
    },
    token::{AuthToken, Token},
};

// TODO: move this to another file?
static REDIS_CLIENT: OnceCell<Arc<RedisClient>> = OnceCell::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountVerification {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub network: String,
    /// AccountType: challengeInfo
    pub challenges: HashMap<AccountType, ChallengeInfo>,
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

    pub fn add_challenge(
        &mut self,
        account_type: &AccountType,
        name: String,
        token: Option<String>,
    ) {
        self.challenges.insert(
            account_type.to_owned(),
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

    pub fn mark_challenge_done(&mut self, account_type: &AccountType) -> anyhow::Result<()> {
        match self.challenges.get_mut(&account_type) {
            Some(challenge) => {
                challenge.done = true;
                challenge.token = None;
                self.updated_at = Utc::now();
                self.complete_all_challenges();
                Ok(())
            }
            None => Err(anyhow!("Unable to mark challenge as done")),
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
    Image(String),
}

impl Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Account::Twitter(name) => write!(f, "twitter|{name}"),
            Account::Discord(name) => write!(f, "discord|{name}"),
            Account::Matrix(name) => write!(f, "matrix|{name}"),
            Account::Display(name) => write!(f, "display|{name}"),
            Account::Legal(name) => write!(f, "legal|{name}"),
            Account::Web(name) => write!(f, "web|{name}"),
            Account::Email(name) => write!(f, "email|{name}"),
            Account::Github(name) => write!(f, "github|{name}"),
            Account::Image(name) => write!(f, "image|{}", name),
            Account::PGPFingerprint(name) => write!(f, "pgp_fingerprint|{}", hex::encode(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    #[serde(alias = "discord", alias = "DISCORD")]
    Discord,
    #[serde(alias = "display_name", alias = "DISPLAY_NAME")]
    #[serde(rename = "DisplayName")]
    Display,
    #[serde(alias = "email", alias = "EMAIL")]
    Email,
    #[serde(alias = "matrix", alias = "MATRIX")]
    Matrix,
    #[serde(alias = "twitter", alias = "TWITTER")]
    Twitter,
    #[serde(alias = "github", alias = "GITHUB")]
    Github,
    #[serde(alias = "legal", alias = "LEGAL")]
    Legal,
    #[serde(alias = "web", alias = "WEB")]
    Web,
    #[serde(alias = "image", alias = "IMAGE")]
    Image,
    #[serde(alias = "pgp_fingerprint", alias = "PGP_FINGERPRINT")]
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
            Self::Image => write!(f, "image"),
        }
    }
}

impl Account {
    pub fn determine(&self) -> ValidationMode {
        match self {
            // Direct: verified directly without user action
            Account::Display(_) | Account::Image(_) => ValidationMode::Direct,
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

    pub async fn generate_token(&self, is_done: bool) -> Option<String> {
        match self {
            Account::Github(_) => {
                // NOTE: this should generate a url for the user to open on the browser and outh
                // our app
                Github::request_url().await
                // NOTE: request url here? so we will save it in this format
                // acc_type|url|network|wallet_id
                // or should we generate the url whenever someone request a state?
            }
            _ => {
                if self.should_skip_token(is_done) {
                    None
                } else {
                    Some(Token::generate().await.show())
                }
            }
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
            Self::Image(_) => AccountType::Image,
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
            | Self::Image(v)
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
            AccountType::Twitter => Self::Twitter(format!("@{value}")),
            AccountType::Github => Self::Github(value),
            AccountType::Legal => Self::Legal(value),
            AccountType::Web => Self::Web(value),
            AccountType::Image => Self::Image(value),
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
        info!(identity_info = %format!("{:?}", value), "Converting IdentityInfo into accounts");
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
        add_if_some(&value.image, Account::Image);

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
        info!("Checking format for {s}");
        match matrix_regex.captures(s) {
            Some(account) => {
                info!(acc_format = %"valid", acc_type = %"matrix", "Account info");
                let acc_name: &str = &account["name"];
                let domain: &str = &account["domain"];
                Ok(Self::Matrix(format!("@{acc_name}:{domain}")))
            }
            None => {
                let (account_type, value) = s
                    .split_once('|')
                    .ok_or_else(|| anyhow::anyhow!("Invalid account format, expected Type:Name"))?;
                let account_type: AccountType = account_type.parse()?;
                info!(acc_format = %"valid", acc_type = %account_type, "Account info");
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, ToSql)]
#[serde(rename_all(serialize = "lowercase"))]
pub enum Network {
    #[serde(alias = "paseo", alias = "PASEO")]
    Paseo,
    #[serde(alias = "polkadot", alias = "POLKADOT")]
    Polkadot,
    #[serde(alias = "kusama", alias = "KUSAMA")]
    Kusama,
    #[serde(alias = "rococo", alias = "ROCOCO")]
    Rococo,
}

impl Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE: this is done for compatibility reasons
        match self {
            Network::Paseo => write!(f, "paseo"),
            Network::Polkadot => write!(f, "polkadot"),
            Network::Kusama => write!(f, "kusama"),
            Network::Rococo => write!(f, "rococo"),
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::Rococo // hmmm?
    }
}

impl<'a> FromSql<'a> for Network {
    fn from_sql(
        _ty: &postgres_types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let s = std::str::from_utf8(raw)?;
        match s {
            "paseo" => Ok(Network::Paseo),
            "polkadot" => Ok(Network::Polkadot),
            "kusama" => Ok(Network::Kusama),
            "rococo" => Ok(Network::Rococo),
            _ => Err(format!("Unrecognized value for Network enum: {}", s).into()),
        }
    }

    fn accepts(ty: &postgres_types::Type) -> bool {
        ty.name().eq_ignore_ascii_case("network")
    }
}

impl Network {
    pub fn from_str(network: &str) -> anyhow::Result<Self> {
        match network {
            "Paseo" | "paseo" => Ok(Self::Paseo),
            "Kusama" | "kusama" => Ok(Self::Kusama),
            "Polkadot" | "polkadot" => Ok(Self::Polkadot),
            "Rococo" | "rococo" => Ok(Self::Rococo),
            _ => Err(anyhow!("Unknown or not supported network '{network}'")),
        }
    }
}

// --------------------------------------
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubscribeAccountStateRequest {
    #[serde(rename = "type")]
    pub _type: RequestType,
    pub payload: AccountId32,
    pub network: Network,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyPGPKeyRequest {
    #[serde(rename = "type")]
    pub _type: RequestType,
    pub pubkey: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub network: Network,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingSubscribeRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingVerifyPGPRequest {
    pub network: Network,
    pub signed_challenge: String,
    pub pubkey: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingSearchRequest {
    pub network: Option<Network>,
    pub outputs: Vec<DisplayedInfo>,
    pub filters: Filter,
}

mod date_format {
    use chrono::NaiveDate;
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%d";

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<NaiveDate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            Some(date_str) => NaiveDate::parse_from_str(&date_str, FORMAT)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }

    pub fn serialize<S>(date: &Option<NaiveDate>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(date) => serializer.serialize_str(&date.format(FORMAT).to_string()),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TimeFilter {
    #[serde(with = "date_format", default)]
    pub gt: Option<chrono::NaiveDate>,
    #[serde(with = "date_format", default)]
    pub lt: Option<chrono::NaiveDate>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
/// Display condition
pub struct Filter {
    pub fields: Vec<FieldsFilter>,
    pub result_size: Option<usize>,
    pub time: Option<TimeFilter>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FieldsFilter {
    pub field: SearchInfo,
    pub strict: bool,
    // starts_with: bool,
    // ends_with: bool,
    // contains: bool,
}

impl FieldsFilter {
    pub fn new(field: SearchInfo, strict: bool) -> Self {
        Self { field, strict }
    }
}

impl Filter {
    pub fn new(
        fields: Vec<FieldsFilter>,
        result_size: Option<usize>,
        time: Option<TimeFilter>,
    ) -> Self {
        Self {
            fields,
            result_size,
            time,
        }
    }
}

impl IncomingSearchRequest {
    pub fn new(network: Option<Network>, outputs: Vec<DisplayedInfo>, filters: Filter) -> Self {
        Self {
            network,
            outputs,
            filters,
        }
    }

    async fn search(self) -> anyhow::Result<Vec<RegistrationRecord>> {
        if self.outputs.contains(&DisplayedInfo::Timeline) {
            let mut registration_query = RegistrationQuery::default();
            let displayed = RegistrationDisplayed::from(&self);
            let condition = RegistrationCondition::from(&self);

            registration_query = registration_query.selected(displayed).condition(condition);

            let mut registrations = registration_query.exec().await?;

            TimelineQuery::supply(
                &mut registrations,
                self.filters.result_size,
                self.filters.time,
            )
            .await?;

            Ok(registrations)
        } else {
            let mut registration_query = RegistrationQuery::default();
            let mut displayed = RegistrationDisplayed::default();
            let mut condition = RegistrationCondition::default();

            for filter in self.filters.fields.iter() {
                condition = condition.filter(filter);
            }

            if let Some(network) = self.network {
                condition = condition.network(&network);
            }

            for output in self.outputs {
                if let Ok(output) = output.try_into() {
                    displayed.push(output);
                }
            }

            if let Some(result_size) = self.filters.result_size {
                displayed = displayed.result_size(result_size);
            }

            registration_query = registration_query.selected(displayed).condition(condition);

            registration_query.exec().await
        }
    }
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
    SubscribeAccountState(IncomingSubscribeRequest),
    VerifyPGPKey(IncomingVerifyPGPRequest),
    SearchRegistration(IncomingSearchRequest),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionedMessage {
    pub version: String,
    #[serde(flatten)]
    pub payload: WebSocketMessage,
}

impl VersionedMessage {
    fn message_type_str(&self) -> &'static str {
        match self.payload {
            WebSocketMessage::SubscribeAccountState(_) => "SubscribeAccountState",
            WebSocketMessage::VerifyPGPKey(_) => "VerifyPGPKey",
            WebSocketMessage::SearchRegistration(_) => "SearchRegistration",
        }
    }
}

// ------------------
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SubscribeAccountState {
    SubscribeAccountState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RequestType {
    SubscribeAccountState,
    VerifyPGPKey,
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

#[instrument(name = "node_listener")]
pub async fn spawn_node_listener() -> anyhow::Result<()> {
    NodeListener::new().await?.listen().await
}

/// Converts the inner of [IdentityData] to a [String]
#[instrument(skip_all)]
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
#[instrument(skip_all)]
fn ss58_to_account_id32<'de, D>(deserializer: D) -> Result<AccountId32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ss58: String = Deserialize::deserialize(deserializer)?;
    AccountId32::from_str(&ss58)
        .map_err(|e| serde::de::Error::custom(format!("Invalid SS58: {e:?}")))
}

#[deprecated]
fn string_to_account_id(s: &str) -> anyhow::Result<AccountId32> {
    AccountId32::from_str(s).map_err(|e| anyhow!("Invalid account ID: {}", e))
}

#[derive(Debug, Clone)]
pub struct SocketListener {
    redis_cfg: RedisConfig,
    span: Span,
    socket_addr: SocketAddr,
}

impl SocketListener {
    pub async fn new() -> Self {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");
        let span = info_span!("socket_listener");
        Self {
            span,
            redis_cfg: cfg.redis.clone(),
            socket_addr: cfg.websocket.socket_addrs().unwrap(),
        }
    }

    #[instrument(skip_all, parent = &self.span, name = "subscription_request")]
    pub async fn handle_subscription_request(
        &mut self,
        request: IncomingSubscribeRequest,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        if !cfg.registrar.is_network_supported(&request.network) {
            return Ok(serde_json::json!({
                "type": "error",
                "message": format!("Network {} not supported", request.network)
            }));
        }

        let network_cfg = cfg
            .registrar
            .get_network(&request.network)
            .ok_or_else(|| anyhow!("Network {} not configured", request.network))?;

        *subscriber = Some(request.account.clone());
        let client = NodeClient::from_url(&network_cfg.endpoint).await?;
        let registration = node::get_registration(&client, &request.account).await?;

        let mut conn = RedisConnection::get_connection().await?;

        // 1) attempt to load existing verification state, if any
        let existing_verification = conn
            .get_verification_state(&request.network, &request.account)
            .await?;

        // 2) if none found, create a fresh AccountVerification
        let mut verification = existing_verification
            .unwrap_or_else(|| AccountVerification::new(request.network.to_string()));

        // get the accounts from the chain's identity info
        let accounts = filter_accounts(
            &registration.info,
            &request.account,
            network_cfg.registrar_index,
            &request.network,
        )
        .await?;

        // 3) for each discovered account, only create a token if we do not
        //    already have one stored. Otherwise, reuse the old token/challenge.
        for (account, is_done) in &accounts {
            let (name, acc_type) = (account.inner(), account.account_type());

            // only add a new challenge if not already present.
            // if *is_done or it's a display_name, we set `token=None` so it's considered done.
            if !verification.challenges.contains_key(&acc_type) {
                let token = account.generate_token(*is_done).await;
                verification.add_challenge(&acc_type, name.clone(), token);
            }
        }

        // save new state
        conn.init_verification_state(&request.network, &request.account, &verification, &accounts)
            .await?;

        // get hash and build state message
        let hash = self.hash_identity_info(&registration.info);

        // return state in json
        conn.build_account_state_message(&request.network, &request.account, Some(hash))
            .await
    }

    /// Generates a hex-encoded blake2 hash of the identity info with 0x prefix
    fn hash_identity_info(&self, info: &IdentityInfo) -> String {
        let encoded_info = info.encode();
        let hash = blake2_256(&encoded_info);
        format!("0x{}", hex::encode(hash))
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn process_v1(
        &mut self,
        message: VersionedMessage,
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        match message.payload {
            WebSocketMessage::SubscribeAccountState(incoming) => {
                self.handle_subscription_request(incoming, subscriber).await
            }
            WebSocketMessage::VerifyPGPKey(incoming) => {
                self.handle_pgp_verification_request(incoming, subscriber)
                    .await
            }
            WebSocketMessage::SearchRegistration(incoming) => {
                self.handle_search_request(incoming).await
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
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

        info!(
            message_version = %versioned_msg.version,
            message_type = %versioned_msg.message_type_str(),
            "Received WebSocket message"
        );

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
        network: &Network,
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

        info!(registration = %format!("{:?}", registration));

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
                Account::Github(github_acc) => (
                    identity_data_tostring(&registration.info.github),
                    github_acc,
                ),
                Account::Legal(_) => todo!(),
                Account::Image(image) => (identity_data_tostring(&registration.info.image), image),
                Account::PGPFingerprint(fingerprint) => (
                    Some(hex::encode(
                        registration
                            .info
                            .pgp_fingerprint
                            .ok_or_else(|| anyhow!("Internal error"))?,
                    )),
                    &hex::encode(fingerprint),
                ),
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

    #[instrument(skip_all)]
    async fn close_ws_connection() {
        info!("Received close frame, closing...");
    }

    #[instrument(skip_all)]
    async fn handle_non_text_message() -> bool {
        info!("Recived non text message");
        true
    }

    #[instrument(skip_all)]
    async fn handle_connection_errors(error: Error) -> bool {
        error!(error = %error, "WebSocket error");
        false
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn process_websocket(
        &mut self,
        ws_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
    ) {
        let mut subscriber: Option<AccountId32> = None;
        let (sender, mut receiver) = mpsc::channel::<serde_json::Value>(100);

        loop {
            tokio::select! {
                Some(msg) = receiver.next() => {
                    if !self.handle_channel_message(&ws_write, msg).await {
                        break;
                    }
                }

                Some(msg_result) = ws_read.next() => {
                    match msg_result {
                        Ok(Message::Close(_)) => {
                            Self::close_ws_connection().await;
                            break;
                        }
                        _ => {
                            if !self.handle_ws_message(&ws_write, msg_result, &mut subscriber, sender.clone()).await {
                                Self::close_ws_connection().await;
                                break;
                            }
                        }
                    }
                }

                else => {
                    info!("WebSocket or channel stream ended");
                    break;
                }
            }
        }

        // Cleanup
        if let Some(id) = subscriber {
            info!(subscriber_id = %id, "Cleaning up subscriber");
        }
        info!("WebSocket connection closed");
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_channel_message(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg: serde_json::Value,
    ) -> bool {
        let resp_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match serde_json::to_string(&msg) {
            Ok(serialized) => {
                info!(response_type = %resp_type, "Sending response");
                match Self::send_message(write, serialized).await {
                    Ok(_) => true,
                    Err(e) => {
                        error!(error = %e, "Failed to send message");
                        false
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize response");
                true
            }
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_ws_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        msg_result: Result<Message, tokio_tungstenite::tungstenite::Error>,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
    ) -> bool {
        match msg_result {
            Ok(Message::Text(bytes)) => {
                // Convert Utf8Bytes to string using to_string()
                let text = bytes.to_string();
                self.handle_text_message(write, text, subscriber, sender)
                    .await
            }
            Ok(Message::Close(_)) => false,
            Ok(_) => Self::handle_non_text_message().await,
            Err(e) => Self::handle_connection_errors(e).await,
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_text_message(
        &mut self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        text: String,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
    ) -> bool {
        match self
            ._handle_incoming(Message::Text(text.into()), subscriber)
            .await
        {
            Ok(response) => {
                let serialized = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize response");
                        return true;
                    }
                };

                if let Err(e) = Self::send_message(write, serialized).await {
                    error!(error = %e, "Failed to send response");
                    return false;
                }

                if let Some(id) = subscriber.take() {
                    info!(subscriber_id = %id, "New subscriber registered");
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
            Err(e) => self.handle_error_response(write, e).await,
        }
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_successful_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        response: serde_json::Value,
        subscriber: &mut Option<AccountId32>,
        sender: Sender<serde_json::Value>,
    ) -> bool {
        debug!("Handling successful response: {:?}", response);

        let serialized = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to serialize response");
                return true;
            }
        };

        let resp_type = response
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        debug!(response_type = %resp_type, "Sending response");

        if let Err(e) = Self::send_message(write, serialized).await {
            error!(error = %e, "Failed to send response");
            return false;
        }

        if let Some(id) = subscriber.take() {
            info!(subscriber_id = %id, "New subscriber registered");
            let mut cloned_self = self.clone();
            tokio::spawn(async move {
                if let Err(e) = cloned_self.spawn_redis_listener(sender, id, response).await {
                    error!(error = %e, "Redis listener error");
                }
            });
        }

        true
    }

    #[instrument(skip_all)]
    async fn handle_error_response(
        &self,
        write: &Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
        error: anyhow::Error,
    ) -> bool {
        error!(error = %error, "Error handling message");

        let error_response = serde_json::json!({
            "version": "1.0",
            "error": error.to_string()
        });

        match serde_json::to_string(&error_response) {
            Ok(serialized) => match Self::send_message(write, serialized).await {
                Ok(_) => true,
                Err(e) => {
                    error!(error = %e, "Failed to send error response");
                    false
                }
            },
            Err(e) => {
                error!(error = %e, "Failed to serialize error response");
                true
            }
        }
    }

    /// Handles incoming websocket connection
    #[instrument(skip_all, parent = &self.span)]
    pub async fn handle_connection(&mut self, stream: std::net::TcpStream) {
        let peer_addr = stream
            .peer_addr()
            .map_or("unknown".to_string(), |addr| addr.to_string());

        info!(
            { peer_addr = peer_addr },
            "New WebSocket connection attempt"
        );

        let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
            Ok(stream) => {
                debug!(
                    { peer_addr = peer_addr },
                    "Successfully converted to tokio TcpStream"
                );
                stream
            }
            Err(e) => {
                error!(error = %e, "Failed to convert to tokio TcpStream");
                return;
            }
        };

        let ws_stream = match tokio_tungstenite::accept_async(tokio_stream).await {
            Ok(stream) => {
                info!("WebSocket handshake successful");
                stream
            }
            Err(e) => {
                error!(error = %e, "WebSocket handshake failed");
                return;
            }
        };

        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        info!("Starting WebSocket message processing");
        self.process_websocket(write, read).await;
    }

    /// websocket listener
    #[instrument(skip_all, fields(peer_addr), parent = &self.span)]
    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let listener = match tokio::net::TcpListener::bind(self.socket_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(address=?self.socket_addr, "Failed to bind to address: {}", e);
                std::process::exit(1);
            }
        };
        info!("WebSocket server listening on {}", self.socket_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!(peer_addr = %addr, "Incoming websocket connection");
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

    #[instrument(skip_all, parent = &self.span)]
    async fn spawn_redis_listener(
        &mut self,
        mut sender: Sender<serde_json::Value>,
        account: AccountId32,
        response: serde_json::Value,
    ) -> anyhow::Result<()> {
        // to avoid collisions with futures::StreamExt
        use tokio_stream::StreamExt;

        let redis_cfg = self.redis_cfg.clone();
        info!(account_id = %account.to_string(), "Starting Redis listener task!");

        tokio::spawn(async move {
            let mut redis_conn = match RedisConnection::get_connection().await {
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

            if let Err(e) = redis_conn.subscribe(&channel).await {
                error!("Unable to subscribe to {} because {:?}", channel, e);
                return;
            };

            // TODO: make this kill iteslf when an completed state is true, since we don't want
            // to listen for events forever!
            debug!("Starting message processing loop");
            let mut stream =
                redis_conn
                    .pubsub_stream()
                    .await
                    .timeout_repeating(tokio::time::interval(Duration::from_secs(
                        redis_cfg.listener_timeout,
                    )));

            while let Some(Ok(msg)) = tokio_stream::StreamExt::next(&mut stream).await {
                debug!("Redis event received: {:?}", msg);

                // process message, continue on error
                let result = match RedisConnection::process_state_change(&msg).await {
                    Ok(result) => result,
                    Err(e) => {
                        error!(error = %e, "Failed to process Redis message {:?}", msg);
                        break;
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
        subscriber: &mut Option<AccountId32>,
    ) -> anyhow::Result<serde_json::Value> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        // filter only supported networks
        if !cfg.registrar.is_network_supported(&request.network) {
            return Err(anyhow!("Network {} not supported", request.network));
        }

        // get network configuration
        let network_cfg = cfg
            .registrar
            .get_network(&request.network)
            .ok_or_else(|| anyhow!("Network {} not configured", request.network))?;

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
            &request.network,
            account_id,
        )
        .await
    }

    async fn handle_search_request(
        &self,
        request: IncomingSearchRequest,
    ) -> anyhow::Result<serde_json::Value> {
        let query: Vec<RegistrationRecord> = request.search().await?;
        Ok(serde_json::to_value(query)?)
    }
}

/// Spawns a websocket server to listen for incoming registration requests
pub async fn spawn_ws_serv() -> anyhow::Result<()> {
    let mut listener = SocketListener::new().await;
    listener.listen().await
}

/// Used to listen/interact with BC events on the substrate node
#[derive(Debug, Clone)]
struct NodeListener {
    clients: HashMap<Network, NodeClient>,
    redis_cfg: RedisConfig,
    span: Span,
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
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        if network_cfg.registrar_index != index {
            return Err(anyhow!(
                "Invalid registrar index on network {network}, expected {} but got {index}",
                network_cfg.registrar_index
            ));
        }

        let client = self
            .clients
            .get(network)
            .ok_or_else(|| anyhow!("No client for network {}", network))?;

        let registration = node::get_registration(client, who).await?;
        let accounts = Account::into_accounts(&registration.info);

        // validation
        SocketListener::check_node(who.clone(), accounts.clone(), network).await?;

        let mut conn = RedisConnection::get_connection().await?;
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
            let (name, acc_type) = (account.inner(), account.account_type());
            let token = account.generate_token(*is_done).await;
            verification.add_challenge(&acc_type, name, token);
        }

        // Save verification state to Redis
        conn.init_verification_state(network, who, &verification, &filtered_accounts)
            .await?;

        // clears all "timelines" related to this requester and reconstruct a new one
        let pog_connection = PostgresConnection::default().await?;
        pog_connection.init_timeline(&who, &network).await?;

        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn handle_node_events(
        &mut self,
        event: EventDetails<SubstrateConfig>,
        network: &Network,
    ) {
        if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
            info!(requester = %req.who, "Judgement requested");

            match self
                .handle_registration(&req.who, req.registrar_index, network)
                .await
            {
                Ok(_) => {
                    info!(requester = %req.who, "Successfully processed registration request")
                }
                Err(e) => {
                    error!(error = %e, requester = %req.who, "Failed to process registration request")
                }
            }
        } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
            info!(requester = %req.who, "Judgement unrequested");

            match self
                .cancel_registration(&req.who, req.registrar_index, network)
                .await
            {
                Ok(_) => {
                    info!(requester = %req.who, "Successfully cancelled registration")
                }
                Err(e) => {
                    error!(error = %e, requester = %req.who, "Failed to cancel registration")
                }
            }
        }
    }

    /// Listens for incoming events on the substrate node, in particular
    /// the `requestJudgement` event
    #[instrument(skip_all, parent = &self.span)]
    pub async fn listen(self) -> anyhow::Result<()> {
        info!("Starting node listener");

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
                            error!(error = %e, "Failed to process block")
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
    #[instrument(skip_all, parent = &self.span)]
    async fn process_block_events(
        &mut self,
        events: subxt::events::Events<SubstrateConfig>,
        block: &Block,
        network: &Network,
    ) {
        for event_result in events.iter() {
            if let Ok(event) = event_result {
                if let Ok(Some(req)) = event.as_event::<JudgementRequested>() {
                    info!(requester = %req.who, "Judgement requested");

                    match self
                        .handle_registration(&req.who, req.registrar_index, network)
                        .await
                    {
                        Ok(_) => {
                            info!(requester = %req.who, "Successfully processed registration request")
                        }
                        Err(e) => {
                            error!(error = %e, requester = %req.who, "Failed to process registration request")
                        }
                    }
                } else if let Ok(Some(req)) = event.as_event::<JudgementUnrequested>() {
                    info!(requester = %req.who, "Judgement unrequested");

                    match self
                        .cancel_registration(&req.who, req.registrar_index, network)
                        .await
                    {
                        Ok(_) => {
                            info!(requester = %req.who, "Successfully cancelled registration")
                        }
                        Err(e) => {
                            error!(error = %e, requester = %req.who, "Failed to cancel registration")
                        }
                    }
                } else if let Ok(Some(jud)) = event.as_event::<JudgementGiven>() {
                    // check if judgement is reasonable
                    if let Ok(Some(judgement)) = get_judgement(&jud.target, network).await {
                        if matches!(judgement, Judgement::Reasonable) {
                            // construct a record
                            let cfg = GLOBAL_CONFIG.get().unwrap();
                            let pog_config = cfg.postgres.clone();
                            let mut pog_connection =
                                PostgresConnection::new(&pog_config).await.unwrap();
                            if let Some(record) =
                                RegistrationRecord::from_judgement(&jud).await.unwrap()
                            {
                                info!(who = ?jud.target.to_string(), "Jugdement saved to DB");
                                info!("Writing registration record to dB after");
                                // write the record
                                pog_connection.save_registration(&record).await.unwrap();
                                let block_index = block.number();
                                let block_hash = block.hash();
                                // mark block
                                pog_connection
                                    .update_indexer_state(
                                        &network,
                                        &block_hash,
                                        &(block_index as i64),
                                    )
                                    .await
                                    .unwrap();
                            }
                            info!(who = ?jud.target.to_string(), "Jugdement saved to DB");
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
    #[instrument(skip_all, parent = &self.span)]
    async fn cancel_registration(
        &self,
        who: &AccountId32,
        index: u32,
        network: &Network,
    ) -> anyhow::Result<()> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let network_cfg = cfg
            .registrar
            .get_network(network)
            .ok_or_else(|| anyhow!("Network {} not configured", network))?;

        if network_cfg.registrar_index != index {
            return Err(anyhow!(
                "Invalid registrar index on network {network}, expected {} but got {index}",
                network_cfg.registrar_index
            ));
        }

        let mut conn = RedisConnection::get_connection().await?;
        conn.clear_all_related_to(network, who).await?;

        let pog_connection = PostgresConnection::default().await?;
        pog_connection.delete_timelines(&who, &network).await?;

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
    pub image: bool,
}

async fn handle_redis_message(msg: &redis::Msg) -> anyhow::Result<()> {
    if let Ok(Some((id, value))) = RedisConnection::process_state_change(msg).await {
        info!("Processed state change for {}: {:?}", id, value);
    }
    Ok(())
}

struct RedisSubscriber {
    redis_cfg: RedisConfig,
    span: Span,
}

impl RedisSubscriber {
    fn new(redis_cfg: RedisConfig) -> Self {
        let span = info_span!("redis_subscriber");
        Self { redis_cfg, span }
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let mut redis_conn = RedisConnection::get_connection().await?;
        redis_conn.subscribe("__keyspace@0__:*").await?;
        let mut stream = redis_conn.pubsub_stream().await;
        while let Some(msg) = stream.next().await {
            info!("Redis event occured");
            if let Err(e) = self.handle_redis_message(msg).await {
                error!(error = %e, "Failed to handle Redis message");
                continue;
            }
        }
        info!("Redis subscription ended");
        Ok(())
    }

    #[instrument(skip_all, parent = &self.span)]
    pub async fn process_state_change(
        &self,
        msg: &redis::Msg,
    ) -> anyhow::Result<Option<(AccountId32, serde_json::Value)>> {
        let mut conn = RedisConnection::get_connection().await?;
        let payload: String = msg.get_payload()?;
        let channel = msg.get_channel_name();

        info!(payload = ?payload, channel = ?channel, "Processing Redis message");

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

        let id = AccountId32::from_str(account_id)?;
        let network = Network::from_str(network)?;

        let account_state = conn
            .build_account_state_message(&network, &id, None)
            .await?;

        Ok(Some((id, account_state)))
    }

    #[instrument(skip_all, parent = &self.span)]
    async fn handle_redis_message(&self, msg: Msg) -> anyhow::Result<()> {
        if let Ok(Some((id, value))) = self.process_state_change(&msg).await {
            info!(
                account_id = %id.to_string(), new_state = %value.to_string(),
                "Processed new state"
            );
        }
        Ok(())
    }
}

pub async fn spawn_redis_subscriber() -> anyhow::Result<()> {
    let redis_cfg = GLOBAL_CONFIG.get().unwrap().redis.clone();
    RedisSubscriber::new(redis_cfg).listen().await
}

fn log_error_and_return(log: String) -> String {
    error!(log);
    log
}

async fn github_oauth_callback(Query(params): Query<GithubRedirectStepTwoParams>) -> String {
    info!(params=?params, "PARAMS");

    // github instance to request acc info
    let gh = match Github::new(&params).await {
        Ok(gh) => gh,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };
    info!(credentials = ?gh, "Github Credentials");

    let gh_username = match gh.request_username().await {
        Ok(username) => username,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };
    info!(username = ?gh_username, "Github Username");

    // checking if url is requested
    let mut redis_connection = match RedisConnection::get_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            return log_error_and_return(format!("Error: {e}"));
        }
    };

    let search_query = format!("github|{gh_username}|*");
    let accounts = match redis_connection.search(&search_query).await {
        Ok(res) => res,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };

    // the reconstructed_url helps identifying the exact relavant registration request
    // like we can have two wallets from different networks registering the same gh acc
    let reconstructed_url = match Github::reconstruct_request_url(&params.state) {
        Ok(url) => url,
        Err(e) => return log_error_and_return(format!("Error: {e}")),
    };

    for acc_str in accounts {
        info!("Account: {}", acc_str);
        let parts: Vec<&str> = acc_str.splitn(4, '|').collect();
        if parts.len() != 4 {
            continue;
        }
        info!("Parts: {:#?}", parts);
        let account = match Account::from_str(&format!("{}|{}", parts[0], parts[1])) {
            Ok(account) => account,
            Err(e) => return log_error_and_return(format!("Error: {e}")),
        };

        let network = match Network::from_str(parts[2]) {
            Ok(network) => network,
            Err(e) => return log_error_and_return(format!("Error: {e}")),
        };

        if let Ok(account_id) = AccountId32::from_str(parts[3]) {
            match <Github as Adapter>::handle_content(
                reconstructed_url.as_str(),
                &mut redis_connection,
                &network,
                &account_id,
                &account,
            )
            .await
            {
                Ok(_) => return String::from("OK"),
                Err(e) => return log_error_and_return(format!("Error: {e}")),
            }
        }
    }

    log_error_and_return("Error: Github account not found in the registration queue".to_string())
}

async fn pong() -> &'static str {
    "PONG"
}

pub async fn spawn_http_serv() -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let gh_config = cfg.adapter.github.clone();
    let http_config = cfg.http.clone();
    let redirect_url = gh_config.redirect_url.unwrap();

    let app = Router::new()
        .route(redirect_url.path(), get(github_oauth_callback))
        .route("/ping", get(pong));
    let listener = tokio::net::TcpListener::bind(&(http_config.host, http_config.port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod unit_test {
    use serde_json::to_string_pretty;

    use crate::api::VersionedMessage;

    #[tokio::test]
    async fn se_de_ws_request() {
        let wallet_id: String = String::from("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty");
        let ws_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "SubscribeAccountState",
            "payload": {
                "network": "paseo",
                "account": wallet_id,
            },
        }))
        .unwrap();

        assert_eq!(
            true,
            serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok()
        );

        let ws_msg = to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "type": "VerifyPGPKey",
            "payload": {
                "network": "paseo",
                "account": wallet_id,
                "pubkey": "asdf",
                "signed_challenge": "asdf",
            },
        }))
        .unwrap();

        assert_eq!(
            true,
            serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok()
        );

        let ws_msg = to_string_pretty(&serde_json::json!({
          "version": "1.0",
          "type": "SearchRegistration",
          "payload": {
              "network": "kusama",
              "outputs": ["WalletID", "Discord", "Timeline"],
              "filters": {
                  "fields": [
                      { "field": { "AccountId32": wallet_id }, "strict": false},
                  ],
                  "result_size": 3,
              }
          }
        }))
        .unwrap();

        assert_eq!(
            true,
            serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok()
        );

        let ws_msg = to_string_pretty(&serde_json::json!({
          "version": "1.0",
          "type": "SearchRegistration",
          "payload": {
              "outputs": [],
              "filters": {
                  "fields": [],
              }
          }
        }))
        .unwrap();

        assert_eq!(
            true,
            serde_json::from_str::<VersionedMessage>(&ws_msg).is_ok()
        );
    }
}

#[instrument(name = "identity_indexer")]
pub async fn spawn_identity_indexer() -> anyhow::Result<()> {
    Indexer::new().await?.index().await
}
