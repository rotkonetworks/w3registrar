#![allow(dead_code)]
use crate::node::identity::events::judgement_requested::RegistrarIndex;
use anyhow::anyhow;
use std::fs;
use url::Url;

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
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl RedisConfig {
    pub fn to_url(&self) -> Result<Url, url::ParseError> {
        let mut url = Url::parse(&format!("redis://{}:{}/", self.host, self.port))?;

        if !self.username.is_empty() || !self.password.is_empty() {
            url.set_username(&self.username)
                .map_err(|()| url::ParseError::IdnaError)?;
            url.set_password(Some(&self.password))
                .map_err(|()| url::ParseError::IdnaError)?;
        }
        Ok(url)
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
