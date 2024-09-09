#![allow(dead_code)]

use crate::node;

pub use crate::node::{AccountId, BlockHash, Client, RegistrarIndex};

use crate::node::substrate::api::runtime_types::pallet_identity::types::Data;
use crate::node::substrate::api::runtime_types::people_rococo_runtime::people::IdentityInfo;
use crate::node::substrate::api::storage;

use anyhow::{Result, Error};
use std::collections::HashSet;
use tokio::sync::mpsc;

pub struct EventSource {
    client: Client,
    registrar_index: RegistrarIndex,
}

impl EventSource {
    pub fn new(client: Client, registrar_index: RegistrarIndex) -> Self {
        Self { client, registrar_index }
    }

    pub async fn fetch_from_block(&self, hash: &str, tx: &mpsc::Sender<Event>) -> Result<()> {
        let hash = hash.parse::<BlockHash>()?;
        let block = self.client.blocks().at(hash).await?;
        self.process_block(block, &tx).await
    }

    pub async fn fetch_incoming(&self, tx: &mpsc::Sender<Event>) -> Result<()> {
        let mut sub = self.client.blocks().subscribe_finalized().await?;
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
                if let Some(id) = self.fetch_identity(&who).await? {
                    Some(Event::JudgementRequested(who, id))
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

    async fn fetch_identity(&self, id: &AccountId) -> Result<Option<Identity>> {
        let query = storage()
            .identity()
            .identity_of(id);

        let identity = self.client
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?;

        if let Some((reg, _)) = identity {
            let identity_info = decode_identity_info(&reg.info)?;
            return Ok(Some(identity_info));
        }
        Ok(None)
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

#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub display_name: Option<String>,
    pub legal: Option<String>,  // Legal name should always be `None`
    pub matrix: Option<String>,
    pub email: Option<String>,
    pub pgp_fingerprint: Option<String>,  // Should be `None` for now
    pub accounts: AccountSet,
}

pub type AccountSet = HashSet<Account>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Account(pub AccountKind, pub Name);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AccountKind {
    Matrix,
    Email,
    Twitter,
    Github,
    Discord,
}

pub type Name = String;

fn decode_identity_info(info: &IdentityInfo) -> Result<Identity, Error> {
    let legal = decode_string_data(&info.legal);
    if legal.is_some() {
        eprintln!("Warning: Legal name is provided but not allowed without proper verification.");
    }

    let pgp_fingerprint = info.pgp_fingerprint.as_ref().map(|fp| hex::encode(fp));
    if pgp_fingerprint.is_some() {
        eprintln!("Warning: PGP Fingerprint is provided but not supported at the moment.");
    }

    let identity = Identity {
        display_name: decode_string_data(&info.display),
        legal: None,  // Always set to None as it's not allowed
        matrix: decode_string_data(&info.matrix),
        email: decode_string_data(&info.email),
        pgp_fingerprint: None,  // Always set to None as it's not supported
        accounts: decode_identity_fields(info),
    };

    Ok(identity)
}

fn decode_identity_fields(info: &IdentityInfo) -> AccountSet {
    use AccountKind::*;
    let mut accounts = HashSet::new();

    decode_identity_field_into(Matrix, &info.matrix, &mut accounts);
    decode_identity_field_into(Email, &info.email, &mut accounts);
    decode_identity_field_into(Twitter, &info.twitter, &mut accounts);
    decode_identity_field_into(Github, &info.github, &mut accounts);
    decode_identity_field_into(Discord, &info.discord, &mut accounts);

    accounts
}

fn decode_identity_field_into(kind: AccountKind, value: &Data, accounts: &mut AccountSet) {
    if let Some(name) = decode_string_data(value) {
        accounts.insert(Account(kind, name));
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
