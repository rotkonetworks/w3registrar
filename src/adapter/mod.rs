use std::fmt::Display;
use subxt::utils::AccountId32;
use tracing::info;

use crate::{
    api::{Account, Network, RedisConnection},
    node::register_identity,
};

pub mod dns;
pub mod mail;
pub mod matrix;
pub mod pgp;

#[derive(Debug, Clone)]
pub enum RegistrationError<'a> {
    WrongChallenge(&'a str),
    AlreadyRegistered(&'a Account, &'a AccountId32, &'a Network),
    NotVerifiable(&'a Account),
    ChallengeDoesNotExist(&'a Account, &'a AccountId32, &'a Network),
    InternalError,
}

impl Display for RegistrationError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrationError::WrongChallenge(challenge) => {
                write!(f, "Wrong challenge {challenge}")
            }
            RegistrationError::NotVerifiable(account) => {
                write!(f, "{} Is not verifiable", account.inner())
            }
            RegistrationError::AlreadyRegistered(account, network, account_id) => {
                write!(
                    f,
                    "{} Is already register under {network}/{account_id}",
                    account.inner()
                )
            }
            RegistrationError::ChallengeDoesNotExist(account, account_id, network) => {
                write!(
                    f,
                    "Challenge does not exist for {} under {network}/{account_id}",
                    account.inner()
                )
            }
            RegistrationError::InternalError => write!(f, "Internal error"),
        }
    }
}

pub trait Adapter {
    async fn handle_content(
        text_content: &str,
        redis_connection: &mut RedisConnection,
        network: &Network,
        account_id: &AccountId32,
        account: &Account,
    ) -> anyhow::Result<()> {
        let account_type = &account.account_type().to_string();

        // get the current state
        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => {
                return Err(anyhow::anyhow!(
                    "{}",
                    RegistrationError::ChallengeDoesNotExist(account, account_id, network)
                ))
            }
        };

        // get the challenge for the account type
        let challenge = match state.challenges.get(account_type) {
            Some(challenge) => challenge,
            None => {
                return Err(anyhow::anyhow!(
                    "{}",
                    RegistrationError::ChallengeDoesNotExist(account, account_id, network)
                ))
            }
        };

        info!("Checking if this challenge is already done...");
        // challenge is already completed
        if challenge.done {
            return Err(anyhow::anyhow!(
                "{}",
                RegistrationError::AlreadyRegistered(account, account_id, network)
            ));
        }

        // verify the token
        let token = match &challenge.token {
            Some(token) => token,
            None => {
                return Err(anyhow::anyhow!(
                    "{}",
                    RegistrationError::NotVerifiable(account)
                ))
            }
        };

        // check if the message matches the token (fixed comparison)
        if text_content != *token {
            return Err(anyhow::anyhow!(
                "{}",
                RegistrationError::WrongChallenge(text_content)
            ));
        }

        // update challenge status
        redis_connection
            .update_challenge_status(network, account_id, account_type)
            .await?;

        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => return Err(anyhow::anyhow!("{}", RegistrationError::InternalError)),
        };

        // register identity if all challenges are completed
        info!("Checking if all challenges are done");
        if state.completed {
            info!("All challenges are completed");
            register_identity(account_id, network).await?;
        }

        Ok(())
    }
}
