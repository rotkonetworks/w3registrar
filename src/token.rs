use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

pub trait AuthToken: PartialEq + Eq {
    /// Generates a token that constitutes of the account and
    /// the expected message to receive from the account
    async fn generate() -> Token;
    fn show(&self) -> String;
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Expected message to recieve
    expected_message: String,
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

impl AuthToken for Token {
    /// Generates a [Token] for a specific [AccountType], this token
    /// constituted of the [AccountType] and the expecetd message as a
    /// [String] 10 characters long
    async fn generate() -> Token {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        Token {
            expected_message: s,
        }
    }

    fn show(&self) -> String {
        self.expected_message.to_owned()
    }
}
