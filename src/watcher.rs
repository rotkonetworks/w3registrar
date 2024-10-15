#![allow(dead_code)]

use crate::node;

use serde::Deserialize;
use tokio_stream::StreamExt;
use std::collections::HashMap;

pub use node::RegistrarIndex;

use node::{Client, Event, BlockHash, Data, IdentityInfo};
use crate::node::{IdentityHash, Judgement, JudgementEnvelope};

const JUDGEMENT_REQUESTED_BLOCK: &str =
    "0xece2b31d1df2d9ff118bb1ced539e395fbabf0987120ff2eed6610d0b7bd6b39";

const SEED_PHRASE: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let client = Client::from_url(cfg.endpoint.as_str()).await?;
    let ri = cfg.registrar_index;

    process_block(&client, ri, JUDGEMENT_REQUESTED_BLOCK).await?;
    // watch_node(&client, ri).await?;

    Ok(())
}

pub async fn process_block(client: &Client, ri: RegistrarIndex, hash: &str) -> anyhow::Result<()> {
    let hash = hash.parse::<BlockHash>()?;
    let block = client.blocks().at(hash).await?;
    for event in node::events_from_block(block).await?.into_iter() {
        handle_event(&client, ri, event).await?;
    }
    Ok(())
}

async fn watch_node(client: &Client, ri: RegistrarIndex) -> anyhow::Result<()> {
    let event_stream = node::subscribe_to_events(&client).await?;
    tokio::pin!(event_stream);

    while let Some(item) = event_stream.next().await {
        let event = item?;
        handle_event(&client, ri, event).await?;
    }

    Ok(())
}

async fn handle_event(client: &Client, ri: RegistrarIndex, event: Event) -> anyhow::Result<()> {
    use node::IdentityEvent::*;

    match event {
        Event::Identity(JudgementRequested { who, registrar_index })
        if registrar_index == ri => {
            use sp_core::Encode;
            use sp_core::blake2_256;

            let reg = node::get_registration(&client, &who).await?;

            // TODO: Clean this up.
            let has_paid_fee = reg
                .judgements
                .0
                .iter()
                .any(|(_, j)| matches!(j, Judgement::FeePaid(_)));

            if has_paid_fee {
                println!("Judgement requested by {}", who);

                let encoded_info = reg.info.encode();
                let hash_bytes = blake2_256(&encoded_info);
                let identity_hash = IdentityHash::from(&hash_bytes);
                println!("Identity hash {:?}", identity_hash);

                let profile = decode_identity_info(&reg.info);
                println!("Profile {:#?}", profile);

                node::provide_judgement(&client, SEED_PHRASE, JudgementEnvelope {
                    registrar_index,
                    target: who,
                    judgement: Judgement::Erroneous,
                    identity_hash,
                }).await?;
            }
        }
        _ => {
            // info!("Ignoring {:?}", event);
        }
    }

    Ok(())
}

//------------------------------------------------------------------------------

pub type Profile = HashMap<ProfileKey, String>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProfileKey {
    DisplayName,
    LegalName,
    PgpFingerprint,
    Matrix,
    Email,
    Twitter,
    Github,
    Discord,
}

fn decode_identity_info(info: &IdentityInfo) -> Profile {
    use ProfileKey::*;

    fn decode_str_field(k: ProfileKey, v: &Data, p: &mut Profile) {
        if let Some(value) = decode_string_data(&v) {
            p.insert(k, value);
        }
    }

    fn decode_hex_field(k: ProfileKey, v: &Option<[u8; 20usize]>, p: &mut Profile) {
        if let Some(bytes) = v {
            p.insert(k, hex::encode(bytes));
        }
    }

    let mut p = Profile::new();
    decode_str_field(DisplayName, &info.display, &mut p);
    decode_str_field(LegalName, &info.legal, &mut p);
    decode_hex_field(PgpFingerprint, &info.pgp_fingerprint, &mut p);
    decode_str_field(Matrix, &info.matrix, &mut p);
    decode_str_field(Email, &info.email, &mut p);
    decode_str_field(Twitter, &info.twitter, &mut p);
    decode_str_field(Github, &info.github, &mut p);
    decode_str_field(Discord, &info.discord, &mut p);
    p
}

fn decode_string_data(data: &Data) -> Option<String> {
    use Data::*;
    match data {
        Raw0(b) => Some(string_from_bytes(b)),
        Raw1(b) => Some(string_from_bytes(b)),
        Raw2(b) => Some(string_from_bytes(b)),
        Raw3(b) => Some(string_from_bytes(b)),
        Raw4(b) => Some(string_from_bytes(b)),
        Raw5(b) => Some(string_from_bytes(b)),
        Raw6(b) => Some(string_from_bytes(b)),
        Raw7(b) => Some(string_from_bytes(b)),
        Raw8(b) => Some(string_from_bytes(b)),
        Raw9(b) => Some(string_from_bytes(b)),
        Raw10(b) => Some(string_from_bytes(b)),
        Raw11(b) => Some(string_from_bytes(b)),
        Raw12(b) => Some(string_from_bytes(b)),
        Raw13(b) => Some(string_from_bytes(b)),
        Raw14(b) => Some(string_from_bytes(b)),
        Raw15(b) => Some(string_from_bytes(b)),
        Raw16(b) => Some(string_from_bytes(b)),
        Raw17(b) => Some(string_from_bytes(b)),
        Raw18(b) => Some(string_from_bytes(b)),
        Raw19(b) => Some(string_from_bytes(b)),
        Raw20(b) => Some(string_from_bytes(b)),
        Raw21(b) => Some(string_from_bytes(b)),
        Raw22(b) => Some(string_from_bytes(b)),
        Raw23(b) => Some(string_from_bytes(b)),
        Raw24(b) => Some(string_from_bytes(b)),
        Raw25(b) => Some(string_from_bytes(b)),
        Raw26(b) => Some(string_from_bytes(b)),
        Raw27(b) => Some(string_from_bytes(b)),
        Raw28(b) => Some(string_from_bytes(b)),
        Raw29(b) => Some(string_from_bytes(b)),
        Raw30(b) => Some(string_from_bytes(b)),
        Raw31(b) => Some(string_from_bytes(b)),
        Raw32(b) => Some(string_from_bytes(b)),
        _ => Option::None,
    }
}

fn string_from_bytes(bytes: &[u8]) -> String {
    std::str::from_utf8(&bytes).unwrap_or("").to_string()
}
