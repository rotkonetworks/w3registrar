#![allow(dead_code)]

use crate::node;

pub use crate::node::{AccountId, BlockHash, RegistrarIndex};

use crate::node::substrate::api::runtime_types::pallet_identity::types::Data;
use crate::node::substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use crate::node::substrate::api::runtime_types::pallet_identity::types::Judgement;
use crate::node::substrate::api::storage;

use anyhow::Result;
use std::collections::HashMap;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub endpoint: String,
    pub registrar_index: RegistrarIndex,
    pub keystore_path: String,
}

pub struct Client {
    inner: node::Client,
    registrar_index: RegistrarIndex,
}

impl Client {
    pub async fn from_config(cfg: ClientConfig) -> Result<Self> {
        Ok(Self {
            inner: node::Client::from_url(cfg.endpoint).await?,
            registrar_index: cfg.registrar_index,
        })
    }

    pub async fn fetch_events_in_block(&self, hash: &str, tx: &mpsc::Sender<Event>) -> Result<()> {
        let hash = hash.parse::<BlockHash>()?;
        let block = self.inner.blocks().at(hash).await?;
        self.process_block(block, &tx).await
    }

    pub async fn fetch_incoming_events(&self, tx: &mpsc::Sender<Event>) -> Result<()> {
        let mut sub = self.inner.blocks().subscribe_finalized().await?;
        while let Some(block) = sub.next().await {
            self.process_block(block?, &tx).await?;
        }
        Ok(())
    }
    
    // PRIVATE

    async fn process_block(&self, block: node::Block, tx: &mpsc::Sender<Event>) -> Result<()> {
        for event in block.events().await?.iter() {
            if let Ok(event) = event?.as_root_event::<node::Event>() {
                if let Some(event) = self.decode_api_event(event).await? {
                    tx.send(event).await?;
                }
            }
        }
        Ok(())
    }

    async fn decode_api_event(&self, event: node::Event) -> Result<Option<Event>> {
        Ok(match event {
            node::Event::Identity(e) => self.decode_api_identity_event(e).await?,
            _ => None,
        })
    }

    async fn decode_api_identity_event(&self, event: node::IdentityEvent) -> Result<Option<Event>> {
        use node::IdentityEvent::*;
        Ok(match event {
            IdentitySet { who } => {
                Some(Event::IdentitySet(who))
            }

            IdentityCleared { who, .. } => {
                Some(Event::IdentityCleared(who))
            }

            IdentityKilled { who, .. } => {
                Some(Event::IdentityKilled(who))
            }

            JudgementRequested { who, registrar_index }
            if registrar_index == self.registrar_index => {
                if let Some((id, is_fee_paid)) = self.fetch_identity(&who).await? {
                    if is_fee_paid {
                        Some(Event::JudgementRequested(who, id))
                    } else {
                        None // Ignore if fee is not paid
                    }
                } else {
                    None
                }
            }

            JudgementUnrequested { who, registrar_index }
            if registrar_index == self.registrar_index => {
                Some(Event::JudgementUnrequested(who))
            }

            JudgementGiven { target, registrar_index }
            if registrar_index == self.registrar_index => {
                Some(Event::JudgementGiven(target))
            }

            _ => None
        })
    }

    async fn fetch_identity(&self, id: &AccountId) -> Result<Option<(Identity, bool)>> {
        let query = storage()
            .identity()
            .identity_of(id);

        let identity = self.inner
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?;

        Ok(identity.and_then(|(reg, _)| {
            let id = decode_identity_info(&reg.info);
            // verify that the account has FeePaid judgement from the registrar in identityOf
            let is_fee_paid = reg.judgements.0
                .iter()
                .any(|(idx, judgement)| {
                    *idx == self.registrar_index && matches!(judgement, Judgement::FeePaid(_))
                });
            Some((id, is_fee_paid))
        }))
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    IdentitySet(AccountId),
    IdentityCleared(AccountId),
    IdentityKilled(AccountId),
    JudgementRequested(AccountId, Identity),
    JudgementUnrequested(AccountId),
    JudgementGiven(AccountId),
}

impl Event {
    pub fn target(&self) -> &AccountId {
        use Event::*;
        match self {
            | IdentitySet(id)
            | IdentityCleared(id)
            | IdentityKilled(id)
            | JudgementRequested(id, _)
            | JudgementUnrequested(id)
            | JudgementGiven(id) => {
                id
            }
        }
    }
}

//------------------------------------------------------------------------------

pub type Identity = HashMap<IdentityKey, String>;

pub type IdentityField = (IdentityKey, String);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IdentityKey {
    DisplayName,
    LegalName,
    PgpFingerprint,
    Matrix,
    Email,
    Twitter,
    Github,
    Discord,
}

fn decode_identity_info(info: &IdentityInfo) -> Identity {
    use IdentityKey::*;
    let mut id = Identity::new();

    decode_identity_string_field_into(DisplayName, &info.display, &mut id);
    decode_identity_string_field_into(LegalName, &info.legal, &mut id);
    decode_identity_hex_field_into(PgpFingerprint, &info.pgp_fingerprint, &mut id);

    decode_identity_string_field_into(Matrix, &info.matrix, &mut id);
    decode_identity_string_field_into(Email, &info.email, &mut id);
    decode_identity_string_field_into(Twitter, &info.twitter, &mut id);
    decode_identity_string_field_into(Github, &info.github, &mut id);
    decode_identity_string_field_into(Discord, &info.discord, &mut id);


    if id.contains_key(&LegalName) {
        warn!("Legal name is provided but not allowed without proper verification.");
    }

    if id.contains_key(&PgpFingerprint) {
        warn!("PGP Fingerprint is provided but not supported at the moment.");
    }

    id
}

fn decode_identity_string_field_into(key: IdentityKey, data: &Data, accounts: &mut Identity) {
    if let Some(value) = decode_string_data(&data) {
        accounts.insert(key, value);
    }
}

fn decode_identity_hex_field_into(key: IdentityKey, data: &Option<[u8; 20usize]>, accounts: &mut Identity) {
    if let Some(bytes) = data {
        accounts.insert(key, hex::encode(bytes));
    }
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
