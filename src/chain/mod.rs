#![allow(dead_code)]

mod substrate;
mod api;

pub use api::AccountId;

use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub type RegistrarIndex = u32;

#[derive(Debug, Clone)]
pub struct Client {
    inner: api::Client,
}

impl Client {
    pub async fn from_url(url: &str) -> Result<Self> {
        Ok(Self { inner: api::Client::from_url(url).await? })
    }

    // TODO: Return a stream instead of fetching into a channel.
    pub async fn fetch_incoming_events(&self, tx: &mpsc::Sender<Event>) -> Result<()> {
        let mut sub = self.inner.blocks().subscribe_finalized().await?;
        while let Some(block) = sub.next().await {
            for event in block?.events().await?.iter() {
                if let Ok(event) = event?.as_root_event::<api::Event>() {
                    tx.send(decode_api_event(event)).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn get_registration(&self, who: &AccountId) -> Result<Registration> {
        let query = api::storage()
            .identity()
            .identity_of(who);

        let identity = self.inner
            .storage()
            .at_latest()
            .await?
            .fetch(&query)
            .await?;

        match identity {
            None => Err(anyhow::anyhow!("No registration found for {}", who)),
            Some((reg, _)) => Ok(decode_registration(reg)),
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Registration {
    pub judgements: Vec<Judgement>,
    pub identity: Identity,
}

impl Registration {
    pub fn has_paid_fee(&self) -> bool {
        self.judgements
            .iter()
            .any(|j| matches!(j, Judgement::FeePaid(_)))
    }

    pub fn last_judgement(&self) -> Option<Judgement> {
        self.judgements.last().cloned()
    }
}

fn decode_registration(reg: api::Registration) -> Registration {
    let judgements = reg.judgements.0
        .iter()
        .map(|(_, j)| decode_judgement(j))
        .collect();

    let identity = decode_identity_info(&reg.info);

    Registration { judgements, identity }
}

//------------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Judgement {
    Unknown,
    FeePaid(u128),
    Reasonable,
    KnownGood,
    OutOfDate,
    LowQuality,
    Erroneous,
}

fn decode_judgement(j: &api::Judgement) -> Judgement {
    match j {
        api::Judgement::Unknown => Judgement::Unknown,
        api::Judgement::FeePaid(x) => Judgement::FeePaid(*x),
        api::Judgement::Reasonable => Judgement::Reasonable,
        api::Judgement::KnownGood => Judgement::KnownGood,
        api::Judgement::OutOfDate => Judgement::OutOfDate,
        api::Judgement::LowQuality => Judgement::LowQuality,
        api::Judgement::Erroneous => Judgement::Erroneous,
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Unknown,
    IdentityChanged(AccountId),
    JudgementRequested(AccountId, RegistrarIndex),
    JudgementUnrequested(AccountId, RegistrarIndex),
    JudgementGiven(AccountId, RegistrarIndex),
}

fn decode_api_event(event: api::Event) -> Event {
    match event {
        api::Event::Identity(e) => {
            use api::IdentityEvent::*;
            match e {
                | IdentitySet { who }
                | IdentityCleared { who, .. }
                | IdentityKilled { who, .. } => {
                    Event::IdentityChanged(who)
                }
                JudgementRequested { who, registrar_index } => {
                    Event::JudgementRequested(who, registrar_index)
                }
                JudgementUnrequested { who, registrar_index } => {
                    Event::JudgementUnrequested(who, registrar_index)
                }
                JudgementGiven { target, registrar_index } => {
                   Event::JudgementUnrequested(target, registrar_index)
                }
                _ => Event::Unknown
            }
        }
        _ => Event::Unknown,
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

fn decode_identity_info(info: &api::IdentityInfo) -> Identity {
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

    id
}

fn decode_identity_string_field_into(key: IdentityKey, data: &api::Data, accounts: &mut Identity) {
    if let Some(value) = decode_string_data(&data) {
        accounts.insert(key, value);
    }
}

fn decode_identity_hex_field_into(key: IdentityKey, data: &Option<[u8; 20usize]>, accounts: &mut Identity) {
    if let Some(bytes) = data {
        accounts.insert(key, hex::encode(bytes));
    }
}

fn decode_string_data(data: &api::Data) -> Option<String> {
    use api::Data::*;
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
