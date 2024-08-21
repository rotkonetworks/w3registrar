#![allow(dead_code)]

use crate::node;
use crate::node::{AccountId, FieldKey, FieldMap, RegistrarIndex};

use anyhow::Result;

#[derive(Debug, Clone)]
pub enum Event {
    GeneratedChallenges(AccountId, FieldMap),
    FieldWasVerified(AccountId, FieldKey),
    ReceivedJudgement(AccountId, Judgement)
}

#[derive(Debug, Clone)]
pub struct Message {
    pub source: Id,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct Judgement;

// TODO: Name?
pub type Id = (FieldKey, String);

pub fn request_judgement(_who: AccountId, _fields: FieldMap) -> Result<()> {
    todo!()
}

pub fn verify_message(_msg: Message) -> Result<()> {
    todo!()
}

pub fn fetch_events(_who: AccountId) -> Result<Vec<Event>> {
    todo!()
}

pub fn handle_node_event(_event: node::Event) -> Result<()> {
    todo!()
}
