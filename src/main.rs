mod matrix;
mod node;
mod registry;

use crate::node::{Command, FieldMap, Judgement};

use anyhow::Result;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing::Level;
use serde::Deserialize;
use uuid::Uuid;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::load_from("config.toml")?;
    let client = node::Client::from_config(config.watcher).await?;

    process_events(&client).await?;
    provide_judgements(&client).await?;

    Ok(())
}

async fn process_events(client: &node::Client) -> Result<()> {
    let events = client.fetch_events().await?;
    for event in events.into_iter() {
        process_event(event, &client).await?;
    }
    Ok(())
}

async fn process_event(event: node::Event, client: &node::Client) -> Result<()> {
    use node::Event::*;

    println!("process {:#?}\n", event);

    match event {
        JudgementRequested(who) => {
            let fields = client.fetch_contact_details(&who).await?;
            let mut challenges = FieldMap::new();
            for k in fields.keys() {
                challenges.insert(*k, generate_challenge());
            }
            registry::save(registry::Event::GeneratedChallenges(who, challenges)).await?;
        }
    };
    Ok(())
}

async fn provide_judgements(client: &node::Client) -> Result<()> {
    let ids = registry::fetch_verified_identities().await?;
    for id in ids.into_iter() {
        client.exec(Command::ProvideJudgement(id.who, Judgement::Good)).await?;
    }
    Ok(())
}

fn generate_challenge() -> String {
    Uuid::new_v4().to_string()
}

//------------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Config {
    pub matrix: matrix::Config,
    pub watcher: node::ClientConfig,
}

impl Config {
    fn load_from(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("Failed to open config `{}`.", path))?;

        toml::from_str::<Self>(&content)
            .map_err(|err| anyhow::anyhow!("Failed to parse config: {:?}", err))
    }
}
