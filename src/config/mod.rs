#![allow(dead_code)]

use crate::api::Network;
use crate::node::identity::events::judgement_requested::RegistrarIndex;
use anyhow::anyhow;
use serde::Deserialize;
use std::collections::HashMap;
use subxt::utils::AccountId32;

use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use tokio::sync::OnceCell;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct Adapter {
    pub matrix: MatrixConfig,
    pub email: EmailConfig,
    pub github: GithubConfig,
    #[serde(default)]
    pub pgp: PGPConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub websocket: WebsocketConfig,
    pub registrar: RegistrarConfigs,
    pub redis: RedisConfig,
    pub http: HTTPConfig,
    pub adapter: Adapter,
    pub postgres: PostgresConfig,
    #[serde(default)]
    pub ratelimit: Ratelimit,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub ranking: RankingConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminConfig {
    /// List of SS58 addresses that can perform admin actions
    #[serde(default)]
    pub allowed_accounts: Vec<String>,
}

/// Search ranking configuration for ordering results
#[derive(Debug, Deserialize, Clone)]
pub struct RankingConfig {
    /// Network weights for ranking (higher = more important)
    #[serde(default)]
    pub network_weights: NetworkWeights,
    /// Verification bonus points
    #[serde(default)]
    pub verification: VerificationWeights,
    /// Similarity score multiplier (0-1 similarity scaled by this)
    #[serde(default = "default_similarity_weight")]
    pub similarity_weight: u32,
}

fn default_similarity_weight() -> u32 {
    200
}

impl Default for RankingConfig {
    fn default() -> Self {
        Self {
            network_weights: NetworkWeights::default(),
            verification: VerificationWeights::default(),
            similarity_weight: 200,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkWeights {
    #[serde(default = "default_polkadot_weight")]
    pub polkadot: u32,
    #[serde(default = "default_kusama_weight")]
    pub kusama: u32,
    #[serde(default = "default_paseo_weight")]
    pub paseo: u32,
    #[serde(default = "default_other_weight")]
    pub other: u32,
}

fn default_polkadot_weight() -> u32 { 100 }
fn default_kusama_weight() -> u32 { 80 }
fn default_paseo_weight() -> u32 { 20 }
fn default_other_weight() -> u32 { 10 }

impl Default for NetworkWeights {
    fn default() -> Self {
        Self {
            polkadot: 100,
            kusama: 80,
            paseo: 20,
            other: 10,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct VerificationWeights {
    /// Bonus for identities verified by our registrar
    #[serde(default = "default_our_registrar")]
    pub our_registrar: u32,
    /// Bonus for identities verified by any registrar
    #[serde(default = "default_any_registrar")]
    pub any_registrar: u32,
}

fn default_our_registrar() -> u32 { 50 }
fn default_any_registrar() -> u32 { 30 }

impl Default for VerificationWeights {
    fn default() -> Self {
        Self {
            our_registrar: 50,
            any_registrar: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ratelimit {
    pub wallet_requests_hour_limit: u64,
    pub ip_requests_hour_limit: u64,
    exceptions: Option<Exceptions>,
}

impl Ratelimit {
    pub fn is_exception(&self, wallet_id: &AccountId32, network: &Network) -> bool {
        match &self.exceptions {
            Some(exceptions) => exceptions
                .wallets
                .contains(&(wallet_id.clone(), network.clone())),
            None => false,
        }
    }

    pub fn is_exception_ip(&self, ip: &IpAddr) -> bool {
        match &self.exceptions {
            Some(exceptions) => exceptions.ips.contains(ip),
            None => false,
        }
    }
}

impl Default for Ratelimit {
    fn default() -> Self {
        Self {
            wallet_requests_hour_limit: 60,
            ip_requests_hour_limit: 60,
            exceptions: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Exceptions {
    wallets: Vec<(AccountId32, Network)>,
    ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailProtocol {
    Imap,
    Jmap,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailMode {
    Receive,      // Only receive and process emails
    Send,         // Only send challenges via email
    Bidirectional, // Both send and receive
}

#[derive(Clone, Deserialize)]
pub struct EmailConfig {
    pub username: String,
    pub password: String,
    pub name: String,
    pub port: u16,
    pub email: String,
    pub mailbox: String,
    pub server: String,
    pub checking_frequency: Option<u64>,
    #[serde(default = "default_email_protocol")]
    pub protocol: EmailProtocol,
    #[serde(default = "default_email_mode")]
    pub mode: EmailMode,
}

// Custom Debug to avoid logging passwords
impl std::fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("name", &self.name)
            .field("port", &self.port)
            .field("email", &self.email)
            .field("mailbox", &self.mailbox)
            .field("server", &self.server)
            .field("checking_frequency", &self.checking_frequency)
            .field("protocol", &self.protocol)
            .field("mode", &self.mode)
            .finish()
    }
}

fn default_email_protocol() -> EmailProtocol {
    EmailProtocol::Imap
}

fn default_email_mode() -> EmailMode {
    EmailMode::Receive
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrarConfigs {
    #[serde(flatten)]
    pub networks: HashMap<Network, RegistrarConfig>,
}

impl RegistrarConfigs {
    pub fn get_network(&self, network: &Network) -> Option<&RegistrarConfig> {
        self.networks.get(network)
    }

    pub fn require_network(&self, network: &Network) -> anyhow::Result<&RegistrarConfig> {
        self.get_network(network)
            .ok_or_else(|| anyhow::anyhow!("Network {} not configured", network))
    }

    pub fn supported_networks(&self) -> Vec<Network> {
        self.networks.keys().cloned().collect()
    }

    pub fn is_network_supported(&self, network: &Network) -> bool {
        self.networks.contains_key(network)
    }

    pub fn registrar_config(&self, reg_index: u32) -> Option<(Network, RegistrarConfig)> {
        self.networks
            .iter()
            .find(|(_, conf)| conf.registrar_index == reg_index)
            .map(|(network, conf)| (network.to_owned(), conf.to_owned()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrarConfig {
    pub endpoint: String,
    /// Whether this registrar is active (can sign judgements)
    /// If false, the chain is only indexed for search but no judgements are processed
    #[serde(default = "default_active")]
    pub active: bool,
    /// Registrar index on this chain (can be 0 for inactive/index-only mode)
    #[serde(default)]
    pub registrar_index: RegistrarIndex,
    /// Registrar account (can be empty for inactive/index-only mode)
    #[serde(default)]
    pub registrar_account: String,
    /// Path to keystore file (only required if active = true)
    #[serde(default)]
    pub keystore_path: String,
    pub fields: Vec<String>,
}

fn default_active() -> bool {
    true
}

static CONFIG: OnceCell<Config> = OnceCell::const_new();

/// Alias for CONFIG for backward compatibility
pub static GLOBAL_CONFIG: &OnceCell<Config> = &CONFIG;

impl Config {
    pub fn load() -> anyhow::Result<Config> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
        let config = Config::load_from(&config_path)?;
        CONFIG
            .set(config.clone())
            .map_err(|_| anyhow!("CONFIG already initialized"))?;
        Ok(config)
    }

    pub fn load_cell() -> OnceCell<Config> {
        CONFIG.clone()
    }

    pub fn load_static<'a>() -> &'a Self {
        CONFIG.get().expect("CONFIG is not initialized")
    }

    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let absolute_path =
            std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
        let content = fs::read_to_string(&absolute_path).map_err(|e| {
            anyhow!(
                "Failed to open config `{}` (absolute path: {:?}): {}",
                path,
                absolute_path,
                e
            )
        })?;
        toml::from_str(&content)
            .map_err(|err| anyhow!("Failed to parse config at {}: {:?}", path, err))
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MatrixConfig {
    pub homeserver: String,
    pub username: String,
    pub password: String,
    pub security_key: String,
    pub admins: Vec<String>,
    pub state_dir: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub listener_timeout: u64,
    pub max_open_clients: u64,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
            listener_timeout: 3500,
            max_open_clients: 100,
            username: None,
            password: None,
        }
    }
}

impl RedisConfig {
    /// Returns a [Url] from the parsed config
    pub fn url(&self) -> anyhow::Result<Url> {
        let mut url = Url::parse(&format!("redis://{}:{}", self.host, self.port))?;

        if let Some(username) = &self.username {
            url.set_username(username)
                .map_err(|_| anyhow::anyhow!("Failed to set Redis username"))?;
        }

        if let Some(password) = &self.password {
            url.set_password(Some(password))
                .map_err(|_| anyhow::anyhow!("Failed to set Redis password"))?;
        }

        Ok(url)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebsocketConfig {
    pub host: String,
    pub port: u16,
}

impl Default for WebsocketConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

impl WebsocketConfig {
    pub fn socket_addrs(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .to_socket_addrs()
            .ok()?
            .next()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GithubConfig {
    /// github application token
    pub client_id: String,
    /// used in the first stage of oauth
    pub gh_url: url::Url,
    /// github client secret
    pub client_secret: String,
    /// url to redirect to when first stage is completed
    pub redirect_url: Option<url::Url>,
}

impl Default for GithubConfig {
    fn default() -> Self {
        let gh_url = url::Url::parse_with_params(
            "https://github.com/login/oauth/authorize",
            &[("client_id", ""), ("redirect_uri", "")],
        )
        .expect("invalid default github oauth url");
        let client_id = String::new();
        let redirect_uri = None;
        let client_secret = String::new();

        Self {
            gh_url,
            client_id,
            redirect_url: redirect_uri,
            client_secret,
        }
    }
}

impl GithubConfig {}

#[derive(Debug, Deserialize, Clone)]
pub struct PGPConfig {
    pub keyserver_url: String,
}

impl Default for PGPConfig {
    fn default() -> Self {
        Self {
            keyserver_url: "https://keyserver.ubuntu.com".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HTTPConfig {
    pub host: String,
    pub port: u16,
    pub gh_endpoint: Option<String>,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        let ip = String::from("0.0.0.0");
        let port: u16 = 3000;
        let gh_endpoint = None;
        Self {
            host: ip,
            port,
            gh_endpoint,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub dbname: String,
    pub cert_path: Option<PathBuf>,
    pub options: Option<String>,
    pub timeout: Option<u64>,
    pub max_connections: Option<u32>,
    /// Read replica host for search queries (optional)
    pub read_replica_host: Option<String>,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        let user = std::env::var("USER").unwrap_or("root".into());
        Self {
            dbname: "postgres".to_string(),
            user: user.to_string(),
            password: None,
            host: "127.0.0.1".to_string(),
            port: 5432,
            cert_path: None,
            options: None,
            timeout: None,
            max_connections: Some(10),
            read_replica_host: None,
        }
    }
}
