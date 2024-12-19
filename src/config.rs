use anyhow::anyhow;
use serde::Deserialize;
use std::fs;

use crate::node::identity::events::judgement_requested::RegistrarIndex;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Nickname(String);

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MatrixConfig {
    pub homeserver: String,
    pub username: String,
    pub password: String,
    pub security_key: String,
    pub admins: Vec<Nickname>,
    pub state_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub timeout: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
    pub proxy_account: String,
    pub registrar_account: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebsocketConfig {
    pub ip: [u8; 4],
    pub port: u16,
}

impl Default for WebsocketConfig {
    fn default() -> Self {
        Self {
            ip: [127, 0, 0, 1],
            port: 8080,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub matrix: MatrixConfig,
    pub redis: RedisConfig,
    pub node: NodeConfig,
    pub websocket: WebsocketConfig,
}

impl Config {
    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow!("Failed to open config `{}`.", path))?;
            
        toml::from_str(&content)
            .map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }

    pub fn redis(&self) -> &RedisConfig {
        &self.redis
    }

    pub fn node(&self) -> &NodeConfig {
        &self.node
    }

    pub fn matrix(&self) -> &MatrixConfig {
        &self.matrix
    }

    pub fn websocket(&self) -> &WebsocketConfig {
        &self.websocket
    }
}
