#![allow(dead_code)]

use crate::node;
use crate::node::{AccountId, Field, FieldKey, FieldMap, Judgement, MaxFee};

use anyhow::Result;
use uuid::Uuid;

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct JudgementRequest {
    pub who: AccountId,
    pub fields: FieldMap,
    pub max_fee: MaxFee,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub who: AccountId,
    pub fields: FieldMap,
}

#[derive(Debug, Clone)]
pub enum Event {
    GeneratedChallenges(AccountId, FieldMap),
    FieldWasVerified(AccountId, FieldKey),
    ReceivedJudgement(AccountId, Judgement)
}

// TODO: Name?
pub type Challenge = (Field, String);

#[derive(Debug, Clone)]
pub struct Message {
    pub source: Field,
    pub body: String,
}

impl Message {
    pub fn new(source: Field, body: String) -> Self {
        Self { source, body }
    }

    pub fn source_key(&self) -> FieldKey {
        self.source.0
    }

    pub fn as_challenge(&self) -> Challenge {
        (self.source.clone(), self.body.clone())
    }
}

// FROM ADAPTERS

pub async fn verify(msg: Message) -> Result<()> {
    if let Some(who) = get_account_id_for(msg.as_challenge()).await? {
        save(Event::FieldWasVerified(who, msg.source_key())).await?;
    }
    Ok(())
}

// FROM NODE

pub async fn handle_node_event(event: node::Event) -> Result<()> {
    use node::Event::*;

    println!("handle {:#?}\n", event);

    match event {
        JudgementRequested(who, fields) => {
            let mut challenges: FieldMap = HashMap::new();
            for k in fields.keys() {
                challenges.insert(*k, generate_challenge());
            }

            let event = Event::GeneratedChallenges(who, challenges);
            save(event).await?;
        }
    };
    Ok(())
}

// TO NODE

pub async fn fetch_verified_identities() -> Result<Vec<Identity>> {
    Ok(vec![])
}

//------------------------------------------------------------------------------
// PRIVATE

async fn save(event: Event) -> Result<()> {
    println!("save {:#?}\n", event);
    Ok(())
}

async fn get_account_id_for(_challenge: Challenge) -> Result<Option<AccountId>> {
    todo!()
}

fn generate_challenge() -> String {
    Uuid::new_v4().to_string()
}
