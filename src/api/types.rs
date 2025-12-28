//! Core types for the W3Registrar API
//!
//! Contains Account, AccountType, Network, and verification-related types.

use crate::adapter::github::Github;
use crate::node::substrate::runtime_types::people_paseo_runtime::people::IdentityInfo;
use crate::token::{AuthToken, Token};
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use postgres_types::{FromSql, ToSql};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use tracing::{debug, info};

/// Matrix ID regex pattern - compiled once at startup
pub static MATRIX_ID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"@(?<name>[a-z0-9][a-z0-9.=/-]*):(?<domain>(?:[a-zA-Z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?)")
        .expect("invalid matrix id regex pattern")
});

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
    #[serde(alias = "name")]
    pub account_name: String,
    pub done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
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
        use crate::config::{EmailMode, EmailProtocol, GLOBAL_CONFIG};

        let cfg = GLOBAL_CONFIG.get();
        let instructions = Self::get_instructions(account_type, &name, cfg);

        let mut challenge_info = ChallengeInfo {
            account_name: name,
            done: token.is_none(),
            token: token.clone(),
            inbound_token: None,
            outbound_token: None,
            instructions,
        };

        if !matches!(account_type, AccountType::Email) {
            self.challenges.insert(account_type.to_owned(), challenge_info);
            self.updated_at = Utc::now();
            self.complete_all_challenges();
            return;
        }

        let cfg = match cfg {
            Some(c) => c,
            None => {
                self.challenges.insert(account_type.to_owned(), challenge_info);
                self.updated_at = Utc::now();
                self.complete_all_challenges();
                return;
            }
        };

        match (&cfg.adapter.email.protocol, &cfg.adapter.email.mode) {
            (EmailProtocol::Jmap, EmailMode::Bidirectional) if token.is_some() => {
                challenge_info.inbound_token = token.clone();
                challenge_info.outbound_token = Some("pending".to_string());
                challenge_info.token = None;
            }
            (EmailProtocol::Jmap, EmailMode::Send) => {
                challenge_info.outbound_token = token.clone();
                challenge_info.token = None;
            }
            _ => {
                challenge_info.inbound_token = token.clone();
                challenge_info.token = None;
            }
        }

        self.challenges.insert(account_type.to_owned(), challenge_info);
        self.updated_at = Utc::now();
        self.complete_all_challenges();
    }

    fn get_instructions(
        account_type: &AccountType,
        name: &str,
        cfg: Option<&crate::config::Config>,
    ) -> Option<String> {
        match account_type {
            AccountType::Email => {
                let registrar_email = cfg.map(|c| c.adapter.email.email.as_str()).unwrap_or("registrar");
                Some(format!(
                    "send email with your token to {} or reply to our verification email",
                    registrar_email
                ))
            }
            AccountType::Matrix => {
                let registrar_matrix = cfg
                    .map(|c| format!("@{}:{}", c.adapter.matrix.username, c.adapter.matrix.homeserver))
                    .unwrap_or_else(|| "@registrar".to_string());
                Some(format!(
                    "send message with your token to {}",
                    registrar_matrix
                ))
            }
            AccountType::Twitter => Some(
                "include your token in a tweet or dm @parity".to_string()
            ),
            AccountType::Discord => Some(
                "send your token in the designated verification channel".to_string()
            ),
            AccountType::Web => {
                if name.contains("gist.github.com") {
                    Some("paste your token in the gist content".to_string())
                } else {
                    Some(format!(
                        "create {}/.well-known/polkadot.txt with your token or add DNS TXT record",
                        name
                    ))
                }
            }
            AccountType::Github => Some(
                "authorize via oauth link provided in token field".to_string()
            ),
            AccountType::PGPFingerprint => Some(
                "sign token with your pgp key and submit via api".to_string()
            ),
            AccountType::Display | AccountType::Legal | AccountType::Image => None,
        }
    }

    fn complete_all_challenges(&mut self) {
        self.completed = !self.challenges.is_empty() && self.challenges.values().all(|c| c.done);
    }

    pub fn mark_challenge_done(&mut self, account_type: &AccountType) -> anyhow::Result<()> {
        match self.challenges.get_mut(account_type) {
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
            Account::Display(_) | Account::Image(_) => ValidationMode::Direct,
            Account::Github(_) | Account::PGPFingerprint(_) => ValidationMode::Inbound,
            Account::Discord(_)
            | Account::Matrix(_)
            | Account::Email(_)
            | Account::Twitter(_)
            | Account::Web(_) => ValidationMode::Outbound,
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
            Account::Github(_) => Github::request_url().await,
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

        let mut add_if_some = |data: &crate::node::substrate::runtime_types::pallet_identity::types::Data, constructor: fn(String) -> Account| {
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
        info!("Checking format for {s}");
        match MATRIX_ID_REGEX.captures(s) {
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, ToSql, Default)]
#[serde(rename_all(serialize = "lowercase"))]
#[postgres(name = "network")]
pub enum Network {
    #[default]
    #[serde(alias = "paseo", alias = "PASEO")]
    #[postgres(name = "paseo")]
    Paseo,
    #[serde(alias = "polkadot", alias = "POLKADOT")]
    #[postgres(name = "polkadot")]
    Polkadot,
    #[serde(alias = "kusama", alias = "KUSAMA")]
    #[postgres(name = "kusama")]
    Kusama,
    #[serde(alias = "rococo", alias = "ROCOCO")]
    #[postgres(name = "rococo")]
    Rococo,
}

impl Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Paseo => write!(f, "paseo"),
            Network::Polkadot => write!(f, "polkadot"),
            Network::Kusama => write!(f, "kusama"),
            Network::Rococo => write!(f, "rococo"),
        }
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

/// Converts the inner of IdentityData to a String
use crate::node::substrate::runtime_types::pallet_identity::types::Data as IdentityData;

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

/// Helper function to deserialize SS58 string into AccountId32
pub fn ss58_to_account_id32<'de, D>(deserializer: D) -> Result<subxt::utils::AccountId32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ss58: String = Deserialize::deserialize(deserializer)?;
    subxt::utils::AccountId32::from_str(&ss58)
        .map_err(|e| serde::de::Error::custom(format!("Invalid SS58: {e:?}")))
}

/// Verify sr25519 signature
pub fn verify_signature(
    account: &subxt::utils::AccountId32,
    message: &[u8],
    signature_hex: &str,
) -> anyhow::Result<()> {
    use sp_core::{crypto::Pair, sr25519};

    let signature_bytes =
        hex::decode(signature_hex).map_err(|e| anyhow!("Invalid signature hex: {}", e))?;

    let signature = sr25519::Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| anyhow!("Invalid sr25519 signature format"))?;

    let public_bytes: [u8; 32] = account.0;
    let public = sr25519::Public::from_raw(public_bytes);

    if sr25519::Pair::verify(&signature, message, &public) {
        Ok(())
    } else {
        Err(anyhow!("Signature verification failed"))
    }
}

