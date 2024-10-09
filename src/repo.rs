#![allow(dead_code)]

use crate::node::AccountId;

use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug, Clone)]
pub struct Person {
    pub id: AccountId,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Account(pub AccountKind, pub Name);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AccountKind {
    Matrix,
    Email,
    Twitter,
    Github,
    Discord,
}

pub type Name = String;

//------------------------------------------------------------------------------

fn generate_secret(_account: &Account) -> Secret {
    // Generate a random alphanumeric string of 8 characters
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}
