#![allow(dead_code)]

use crate::node::{AccountId, Identity, IdentityField, IdentityKey};

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

fn generate_challenges(id: Identity) -> Vec<Challenge> {
    id.into_iter()
        .filter_map(challenge_for_field)
        .collect()
}

fn challenge_for_field(field: IdentityField) -> Option<Challenge> {
    account_for_field(field).map(|acc| {
        Challenge::new(acc.clone(), generate_secret(&acc))
    })
}

fn account_for_field((k, v): IdentityField) -> Option<Account> {
    account_kind_for_key(k).map(|kind| Account(kind, v))
}

fn account_kind_for_key(key: IdentityKey) -> Option<AccountKind> {
    match key {
        IdentityKey::Matrix => Some(AccountKind::Matrix),
        IdentityKey::Email => Some(AccountKind::Email),
        IdentityKey::Twitter => Some(AccountKind::Twitter),
        IdentityKey::Github => Some(AccountKind::Github),
        IdentityKey::Discord => Some(AccountKind::Discord),
        _ => None,
    }
}

fn generate_secret(_account: &Account) -> Secret {
    // Generate a random alphanumeric string of 8 characters
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}
