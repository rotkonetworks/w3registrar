#![allow(dead_code)]
use crate::node::identity::events::judgement_requested::RegistrarIndex;
use anyhow::anyhow;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use url::{ParseError, Url};

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
    // TODO: handle the `unwrap` calls
    /// Returns a [Url] from the parsed config
    pub fn url(&self) -> anyhow::Result<Url, ParseError> {
        let mut url = Url::parse(&format!("redis://{}:{}", self.host, self.port))?;
        match &self.username {
            Some(username) => url.set_username(&username).unwrap(),
            _ => {}
        }
        match &self.password {
            Some(password) => url.set_password(Some(&password)).unwrap(),
            _ => {}
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

impl WebsocketConfig {
    pub fn socket_addrs(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .to_socket_addrs()
            .unwrap()
            .next()
    }
}
