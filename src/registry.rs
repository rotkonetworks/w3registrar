#![allow(dead_code)]

use crate::chain;
use crate::chain::{Account, AccountId, AccountSet};
use rand::{distributions::Alphanumeric, Rng};

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
        chain::Event::JudgementRequested(who, id) => {
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
    // Generate a random alphanumeric string of 8 characters
    let secret: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    secret
}
