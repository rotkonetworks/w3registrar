#![allow(dead_code)]

use crate::chain;
use crate::chain::{Account, AccountId, AccountSet};

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Person {
    pub id: AccountId,
    pub display_name: Option<String>,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub target: Account,
    pub secret: Secret,
}

impl Challenge {
    pub fn new(target: Account, secret: Secret) -> Self {
        Self { target, secret }
    }
}

pub type Secret = String;

pub async fn handle_chain_event(event: chain::Event) -> anyhow::Result<()> {
    match event {
        chain::Event::JudgementRequested(who,  id) => {
            let person = Person {
                id: who,
                display_name: id.display_name,
                challenges: generate_challenges(id.accounts),
            };
            dbg!(&person);
        }
        _ => {}
    };

    Ok(())
}

fn generate_challenges(accounts: AccountSet) -> Vec<Challenge> {
    accounts.iter()
        .map(|acc| Challenge::new(acc.clone(), generate_secret(acc)))
        .collect()
}

fn generate_secret(_account: &Account) -> Secret {
    Uuid::new_v4().to_string()
}
