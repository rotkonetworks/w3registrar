#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Config {
    pub domain: String,
    pub port: u16,
}
