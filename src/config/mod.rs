#![allow(dead_code)]
use crate::node::identity::events::judgement_requested::RegistrarIndex;
use anyhow::anyhow;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::sync::OnceCell;
use url::Url;

#[derive(Debug, Deserialize, Clone)]
pub struct Adapter {
    pub matrix: MatrixConfig,
    pub email: EmailConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub websocket: WebsocketConfig,
    pub registrar: RegistrarConfigs,
    pub redis: RedisConfig,
    pub postgres: PgConfig,
    pub adapter: Adapter,
}

#[derive(Debug, Clone, Deserialize)]
pub struct  PgConfig {
    pub database_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub username: String,
    pub password: String,
    pub name: String,
    pub port: u16,
    pub email: String,
    pub mailbox: String,
    pub server: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrarConfigs {
    #[serde(flatten)]
    pub networks: HashMap<String, RegistrarConfig>,
}

impl RegistrarConfigs {
    pub fn get_network(&self, network: &str) -> Option<&RegistrarConfig> {
        self.networks.get(network)
    }

    pub fn supported_networks(&self) -> Vec<String> {
        self.networks.keys().cloned().collect()
    }

    pub fn is_network_supported(&self, network: &str) -> bool {
        self.networks.contains_key(network)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrarConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub registrar_account: String,
    pub keystore_path: String,
    pub fields: Vec<String>,
}

impl Config {
    /// Set the [GLOBAL_CONFIG] global variable and return an instance(clone) of it
    pub fn set_global_config() -> anyhow::Result<Config> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
        let config = Config::load_from(&config_path)?;
        GLOBAL_CONFIG
            .set(config.clone())
            .expect("GLOBAL_CONFIG already initialized");
        Ok(config)
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

pub static GLOBAL_CONFIG: OnceCell<Config> = OnceCell::const_new();

pub async fn initialize_config() {
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_from(&config_path).expect("Failed to load config");
    GLOBAL_CONFIG
        .set(config)
        .expect("GLOBAL_CONFIG already initialized");
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
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
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
            .unwrap()
            .next()
    }
}
