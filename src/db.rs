#![allow(dead_code)]

use crate::node::{AccountId, BlockHash, BlockNumber};

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Block {
    pub number: BlockNumber,
    pub hash: BlockHash,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EventTag {
    IdentitySet,
    IdentityCleared,
    IdentityKilled,
    JudgementRequested,
    JudgementUnrequested,
    JudgementGiven,
}

impl Event {
    pub fn tag(&self) -> EventTag {
        use Event::*;
        match self {
            IdentitySet(_) => EventTag::IdentitySet,
            IdentityCleared(_) => EventTag::IdentityCleared,
            IdentityKilled(_) => EventTag::IdentityKilled,
            JudgementRequested(_) => EventTag::JudgementRequested,
            JudgementUnrequested(_) => EventTag::JudgementUnrequested,
            JudgementGiven(_) => EventTag::JudgementGiven,
        }
    }

    pub fn target(&self) -> &AccountId {
        use Event::*;
        match self {
            | IdentitySet(id)
            | IdentityCleared(id)
            | IdentityKilled(id)
            | JudgementRequested(id)
            | JudgementUnrequested(id)
            | JudgementGiven(id) => {
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
pub struct AccountState {
    pub tag: EventTag,
    pub source: BlockNumber,
}

impl AccountState {
    pub fn new(tag: EventTag, source: BlockNumber) -> Self {
        Self { tag, source }
    }
}

//------------------------------------------------------------------------------

pub async fn process_block(block: Block) -> Result<()> {
    for event in block.events.into_iter() {
        handle_event(event, block.number).await?;
    }
    Ok(())
}

pub async fn get_last_block_hash() -> Result<Option<BlockHash>> {
    let h = "0x34b869a8c2bbc55337a923e2e517851abe33ea06797292b05e2b79570f821c80".parse::<BlockHash>()?;
    Ok(Some(h))
}

async fn handle_event(event: Event, source: BlockNumber) -> Result<()> {
    let new_state = AccountState::new(event.tag(), source);

    match get_account_state(event.target()).await? {
        None => {
            save_account_state(event.target(), new_state).await?;
        }
        Some(state) => {
            // If this state change comes from a more recent block, keep it,
            // otherwise discard it.
            if source > state.source {
                let state = AccountState::new(event.tag(), source);
                save_account_state(event.target(), state).await?;
            }
        }
    };

    Ok(())
}

//------------------------------------------------------------------------------
// DB - WRITE

async fn save_block(_block: &Block) -> Result<()> {
    todo!()
}

async fn save_account_state(_id: &AccountId, _state: AccountState) -> Result<()> {
    todo!()
}

//------------------------------------------------------------------------------
// DB - READ

async fn get_account_state(_id: &AccountId) -> Result<Option<AccountState>> {
    todo!()
}

async fn get_pending_events() -> Result<Vec<Event>> {
    todo!()
}
