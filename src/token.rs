#![allow(dead_code)]

use rand::prelude::*;
use serde::{Deserialize, Serialize};

const OLC_ALPHABET: &str = "23456789CFGHJKLMNPQRVWXY";

pub trait AuthToken: PartialEq + Eq {
    /// Generates a token that constitutes the account and
    /// the expected message to receive from the account
    async fn generate() -> Token;
    /// Shows generated token string
    fn show(&self) -> String;
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Expected message to receive
    expected_message: String,
}

impl Token {
    pub fn new(token: String) -> Self {
        Self {
            expected_message: token,
        }
    }
}

impl From<String> for Token {
    fn from(value: String) -> Self {
        Self {
            expected_message: value,
        }
    }
}

impl<'a> From<&'a str> for Token {
    fn from(value: &'a str) -> Self {
        Self {
            expected_message: value.to_owned(),
        }
    }
}

impl Token {
    pub fn generate_sync(length: usize) -> String {
        let mut rng = rand::rng();
        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..OLC_ALPHABET.len());
                OLC_ALPHABET.chars().nth(idx).unwrap()
            })
            .collect()
    }
}

impl AuthToken for Token {
    /// Generates a [Token] as a [String] 8 characters long, using the base-20 `OLC_ALPHABET`.
    async fn generate() -> Token {
        Token {
            expected_message: Self::generate_sync(8),
        }
    }

    fn show(&self) -> String {
        self.expected_message.to_owned()
    }
}
