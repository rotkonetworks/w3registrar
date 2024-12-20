use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub ip: [u8; 4],
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip: [127, 0, 0, 1],
            port: 8080,
        }
    }
}
