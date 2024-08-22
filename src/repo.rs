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

impl Event {
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

pub async fn save_block(db: &Db, block: &Block) -> Result<()> {
    insert_block(db, BlockRow {
        number: block.number as usize,
        // BlockHash::to_string() truncates the hash with ellipses.
        hash: format!("{:#?}", block.hash),
        event_count: block.events.len(),
    }).await
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

async fn insert_block(db: &Db, row: BlockRow) -> Result<()> {
    db.call(move |db| {
        db.execute(
            "insert or replace into blocks (number, hash, event_count) \
            values (?1, ?2, ?3)",
            params![row.number, row.hash, row.event_count],
        )?;
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
