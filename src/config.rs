use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub matrix: MatrixConfig,
    pub watcher: WatcherConfig,
}

#[derive(Debug, Deserialize)]
pub struct MatrixConfig {
    pub homeserver: String,
    pub username: String,
    pub password: String,
    pub security_key: String,
    pub admins: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: u32,
    pub keystore_path: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read config file")?;
        toml::from_str(&content)
            .context("Failed to parse config file")
    }
}
