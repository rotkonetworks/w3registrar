mod api;
mod matrix;
mod node;
mod token;
mod config;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    api::spawn_services(config).await
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use redis::Client;

    #[tokio::test]
    async fn test_redis_connection() -> Result<()> {
        println!("Testing Redis connection...");

        let config = Config::load_from("config.toml")?;
        let client = Client::open(config.redis.url()?)?;
        
        let mut conn = client.get_connection()?;
        redis::cmd("PING").query::<String>(&mut conn)?;

        println!("Redis connection test successful");
        Ok(())
    }
}
