use std::fmt::Display;
use subxt::utils::AccountId32;
use tracing::{info, warn};

use crate::{
    api::{Account, AccountType, Network},
    node::register_identity,
    postgres::PostgresConnection,
    rate_limit::get_rate_limiter,
    redis::RedisConnection,
};

pub mod email;
pub mod github;
pub mod matrix;
pub mod pgp;
pub mod web;

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
        let account_type = &account.account_type();
        let pog_connection = PostgresConnection::default().await?;

        // Check rate limit before processing
        let rate_limiter = get_rate_limiter();
        let network_str = network.to_string();
        let account_str = account_id.to_string();
        let field_str = account_type.to_string();

        // Check and record the attempt
        rate_limiter.check_and_record_attempt(&network_str, &account_str, &field_str).await?;

        info!(
            "Token validation attempt for {}/{}/{} - {} attempts remaining",
            network, account_id, account_type,
            rate_limiter.get_remaining_attempts(&network_str, &account_str, &field_str).await
        );

        let state = redis_connection
            .get_verification_state(network, account_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    RegistrationError::ChallengeDoesNotExist(account, account_id, network)
                )
            })?;

        let challenge = state.challenges.get(&account_type)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    RegistrationError::ChallengeDoesNotExist(account, account_id, network)
                )
            })?;

        if challenge.done {
            return Err(anyhow::anyhow!(
                "{}",
                RegistrationError::AlreadyRegistered(account, account_id, network)
            ));
        }

        let valid = match account_type {
            AccountType::Email => {
                [&challenge.inbound_token, &challenge.outbound_token, &challenge.token]
                    .iter()
                    .filter_map(|t| t.as_ref())
                    .any(|token| text_content == token)
            },
            _ => challenge.token.as_ref().map_or(false, |t| text_content == t)
        };

        if !valid {
            warn!(
                "Invalid token attempt for {}/{}/{} - {} attempts remaining",
                network, account_id, account_type,
                rate_limiter.get_remaining_attempts(&network_str, &account_str, &field_str).await
            );
            return Err(anyhow::anyhow!(
                "{}",
                RegistrationError::WrongChallenge(text_content)
            ));
        }

        // Token is valid, reset rate limit for this field
        rate_limiter.reset_attempts(&network_str, &account_str, &field_str).await;
        info!(
            "Valid token for {}/{}/{} - rate limit reset",
            network, account_id, account_type
        );

        // update challenge status
        redis_connection
            .update_challenge_status(network, account_id, account_type)
            .await?;

        // save timeline info
        pog_connection
            .update_timeline(account_type.into(), account_id, network)
            .await?;

        let state = redis_connection
            .get_verification_state(network, account_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{}", RegistrationError::InternalError))?;

        if state.completed {
            register_identity(account_id, network).await?;
            pog_connection
                .finalize_timeline(account_id, network)
                .await?;
        }

        Ok(())
    }
}
