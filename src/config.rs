use std::fs;
use serde::Deserialize;
use anyhow::{anyhow, Result};

use crate::node;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    // pub matrix: matrix::Config,
    pub watcher: WatcherConfig,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WatcherConfig {
    pub endpoint: String,
    pub registrar_index: node::RegistrarIndex,
    pub keystore_path: String,
}

impl Config {
    /// Used to read a the config file for the registrar from 
    /// the provided `path`
    pub fn load_from(path: &str) -> Result<Self> {
        let content =
            fs::read_to_string(path).map_err(|_| anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content).map_err(|err| anyhow!("Failed to parse config: {:?}", err))
    }
}
