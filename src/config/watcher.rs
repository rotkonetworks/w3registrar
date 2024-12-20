#![allow(dead_code)]

use crate::node::identity::events::judgement_requested::RegistrarIndex;
use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}
