#![allow(dead_code)]
use crate::node::identity::events::judgement_requested::RegistrarIndex;
use anyhow::anyhow;
use std::fs;
use toml;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub matrix: MatrixConfig,
    pub websocket: WebsocketConfig,
    pub watcher: WatcherConfig,
    pub redis: RedisConfig,
}

impl Config {
    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let content =
            fs::read_to_string(path).map_err(|_| anyhow!("Failed to open config `{}`.", path))?;
        toml::from_str(&content).map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RedisConfig {
    pub ip: [u8; 4],
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            ip: [127, 0, 0, 1],
            port: 6379,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl RedisConfig {
    pub fn to_full_domain(&self) -> String {
        if !self.username.is_empty() || !self.password.is_empty() {
            return format!(
                "redis://{}:{}@{}.{}.{}.{}:{}/",
                self.username,
                self.password,
                self.ip[0],
                self.ip[1],
                self.ip[2],
                self.ip[3],
                self.port
            );
        } else {
            return format!(
                "redis://{}.{}.{}.{}:{}/",
                self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port
            );
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

#[derive(Debug, Deserialize)]
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
