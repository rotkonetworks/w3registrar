#![allow(dead_code)]

use crate::node::{AccountId, BlockHash, BlockNumber};

use tokio_rusqlite::{params, Connection};
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

const DB_SCHEMA: &str = include_str!("db_schema.sql");

#[derive(Debug, Clone)]
pub struct Database {
    con: Connection,
}

impl Database {
    pub async fn open(path: &str) -> Result<Self> {
        let con = Connection::open(path).await?;

        con.call(|db| {
            db.execute(DB_SCHEMA, [])?;
            Ok(())
        }).await?;

        Ok(Self { con })
    }

    pub async fn save_block(&self, block: Block) -> Result<()> {
        self.con.call(move |db| {
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

    pub async fn get_last_block_hash(&self) -> Result<Option<BlockHash>> {
        let opt_hash = self.con.call(|db| {
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
        }).await?;

        Ok(match opt_hash {
            None => None,
            Some(hash) => Some(hash.parse::<BlockHash>()?),
        })
    }
}