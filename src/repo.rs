#![allow(dead_code)]

use crate::node::{AccountId, BlockHash, BlockNumber};

pub use tokio_rusqlite::Connection as Db;
use tokio_rusqlite::params;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Block {
    pub number: BlockNumber,
    pub hash: BlockHash,
    pub events: Vec<Event>,
}

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
pub enum EventKind {
    IdentitySet,
    IdentityCleared,
    IdentityKilled,
    JudgementRequested,
    JudgementUnrequested,
    JudgementGiven,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        use Event::*;
        match self {
            IdentitySet(_) => EventKind::IdentitySet,
            IdentityCleared(_) => EventKind::IdentityCleared,
            IdentityKilled(_) => EventKind::IdentityKilled,
            JudgementRequested(_) => EventKind::JudgementRequested,
            JudgementUnrequested(_) => EventKind::JudgementUnrequested,
            JudgementGiven(_) => EventKind::JudgementGiven,
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

pub async fn open_db(path: &str) -> Result<Db> {
    let db = Db::open(path).await?;
    apply_schema(&db).await?;
    Ok(db)
}

pub async fn save_block(db: &Db, block: Block) -> Result<()> {
    db.call(move |db| {
        let tx = db.transaction()?;

        let block_number = block.number as usize;
        // BlockHash::to_string() truncates the hash with ellipses.
        let block_hash = format!("{:?}", block.hash);
        let event_count = block.events.len();

        tx.execute(
            "insert or replace into blocks (number, hash, event_count) \
            values (?1, ?2, ?3)",
            params![block_number, block_hash, event_count],
        )?;

        for (i, event) in block.events.into_iter().enumerate() {
            let number = i + 1;
            let kind = format!("{:?}", event.kind());
            let account_id = event.target().to_string();

            tx.execute(
                "insert or replace into events (block_number, number, kind, account_id) \
            values (?1, ?2, ?3, ?4)",
                params![block_number, number, kind, account_id],
            )?;
        }

        tx.commit()?;

        Ok(())
    }).await?;

    Ok(())
}

pub async fn get_last_block_hash(db: &Db) -> Result<Option<BlockHash>> {
    Ok(match select_last_block_hash(db).await? {
        None => None,
        Some(hash) => Some(hash.parse::<BlockHash>()?),
    })
}

//------------------------------------------------------------------------------
// DATABASE

const DB_SCHEMA: &str = include_str!("db_schema.sql");

// WRITE

#[derive(Debug, Clone)]
struct BlockRow {
    number: usize,
    hash: String,
    event_count: usize,
}

async fn apply_schema(db: &Db) -> Result<()> {
    db.call(|db| {
        db.execute(DB_SCHEMA, [])?;
        Ok(())
    }).await?;

    Ok(())
}

// READ

async fn select_last_block_hash(db: &Db) -> Result<Option<String>> {
    Ok(db.call(|db| {
        let mut st = db.prepare(
            "select hash from blocks order by number desc limit 1"
        )?;
        let mut rows = st.query([])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let hash: String = row.get(0)?;
                Ok(Some(hash))
            }
        }
    }).await?)
}
