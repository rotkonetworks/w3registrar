#![allow(dead_code)]

use crate::watcher::AccountId;

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Block {
    pub number: u64,
    pub hash: String,
    pub events: Vec<Event>,
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    IdentitySet(AccountId),
    IdentityCleared(AccountId),
    IdentityKilled(AccountId),
    JudgementRequested(AccountId),
    JudgementUnrequested(AccountId),
    JudgementGiven(AccountId),
}

impl Event {
    pub fn target(&self) -> &AccountId {
        match self {
            | Event::IdentitySet(id)
            | Event::IdentityCleared(id)
            | Event::IdentityKilled(id)
            | Event::JudgementRequested(id)
            | Event::JudgementUnrequested(id)
            | Event::JudgementGiven(id) => {
                id
            }
        }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Account {
    pub id: AccountId,
    pub state: AccountState,
}

impl Account {
    pub fn new(id: AccountId, state: AccountState) -> Self {
        Self { id, state }
    }
}

//------------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AccountState {
    IdentitySet,
    IdentityCleared,
    IdentityKilled,
    JudgementRequested,
    JudgementUnrequested,
    JudgementGiven,
}

impl From<&Event> for AccountState {
    fn from(e: &Event) -> Self {
        use AccountState::*;
        match e {
            Event::IdentitySet(_) => IdentitySet,
            Event::IdentityCleared(_) => IdentityCleared,
            Event::IdentityKilled(_) => IdentityKilled,
            Event::JudgementRequested(_) => JudgementRequested,
            Event::JudgementUnrequested(_) => JudgementUnrequested,
            Event::JudgementGiven(_) => JudgementGiven
        }
    }
}

//------------------------------------------------------------------------------
// WRITE

pub fn begin_transaction() {}

pub fn end_transaction() {}

pub fn save_block(_block: &Block) -> Result<()> {
    todo!()
}

pub fn set_account_state(_id: &AccountId, _state: AccountState) -> Result<()> {
    todo!()
}

//------------------------------------------------------------------------------
// READ

pub fn get_last_block_hash() -> Result<Option<String>> {
    todo!()
}

pub fn get_pending_events() -> Result<Vec<Event>> {
    todo!()
}

