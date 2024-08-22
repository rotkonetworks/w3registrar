mod matrix;
mod node;
mod registry;

use crate::node::{Block, Client, Command, FieldMap, Judgement};

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
    let client = Client::from_config(config.watcher).await?;

    // Get block 96
    let block = client.fetch_block("0x4b38b6dd8e225ff3bb0b906badeedaba574d176aa34023cf64c3649767db7e65").await?;
    process_block(&client, block).await?;
    provide_judgements(&client).await?;

    Ok(())
}

async fn process_block(client: &Client, block: Block) -> Result<()> {
    for event in block.events.into_iter() {
        process_event(event, &client).await?;
    }
    Ok(())
}

async fn process_event(event: node::Event, client: &Client) -> Result<()> {
    use node::Event::*;

    println!("process {:#?}\n", event);

    match event {
        JudgementRequested(who) => {
            if let Some(fields) = client.fetch_contact_details(&who).await? {
                let mut challenges = FieldMap::new();
                for k in fields.keys() {
                    challenges.insert(*k, generate_challenge());
                }
                registry::save(registry::Event::GeneratedChallenges(who, challenges)).await?;
            }
        }
        _ => {}
    };
    Ok(())
}

async fn provide_judgements(client: &Client) -> Result<()> {
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
