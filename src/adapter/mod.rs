use std::fmt::Display;
use subxt::utils::AccountId32;
use tracing::info;

use crate::api::{Account, Network};

pub mod context;
pub mod dns;
pub mod github;
pub mod mail;
pub mod matrix;
pub mod pgp;

pub use context::{ChainRegistrar, TimelineStore, VerificationStore};

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

/// Result of handling adapter content
#[derive(Debug, Clone, PartialEq)]
pub enum HandleResult {
    /// Challenge verified, not all challenges complete yet
    ChallengeVerified,
    /// All challenges complete, identity registered on-chain
    IdentityRegistered,
}

/// Core verification logic that can be tested independently
pub async fn handle_verification<V, T, C>(
    text_content: &str,
    verification_store: &mut V,
    timeline_store: &T,
    chain_registrar: &C,
    network: &Network,
    account_id: &AccountId32,
    account: &Account,
) -> anyhow::Result<HandleResult>
where
    V: VerificationStore,
    T: TimelineStore,
    C: ChainRegistrar,
{
    let account_type = account.account_type();

    // get the current state
    let state = match verification_store
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
    let challenge = match state.challenges.get(&account_type) {
        Some(challenge) => challenge,
        None => {
            return Err(anyhow::anyhow!(
                "{}",
                RegistrationError::ChallengeDoesNotExist(account, account_id, network)
            ))
        }
    };

    info!("Checking if this challenge is already done...");
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

    // check if the message matches the token
    if text_content != *token {
        return Err(anyhow::anyhow!(
            "{}",
            RegistrationError::WrongChallenge(text_content)
        ));
    }

    // update challenge status
    verification_store
        .update_challenge_status(network, account_id, &account_type)
        .await?;

    // save timeline info
    timeline_store
        .update_timeline((&account_type).into(), account_id, network)
        .await?;

    // re-fetch state to check completion
    let state = match verification_store
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
        chain_registrar.register_identity(account_id, network).await?;
        info!("Identity registered on chain");

        timeline_store
            .finalize_timeline(account_id, network)
            .await?;
        info!("Registration timeline updated");

        return Ok(HandleResult::IdentityRegistered);
    }

    Ok(HandleResult::ChallengeVerified)
}

/// Adapter trait - now uses the abstracted handle_verification function
pub trait Adapter {
    /// Handle content using real Redis, Postgres, and chain connections
    async fn handle_content(
        text_content: &str,
        redis_connection: &mut crate::redis::RedisConnection,
        network: &Network,
        account_id: &AccountId32,
        account: &Account,
    ) -> anyhow::Result<()> {
        let pg_conn = crate::postgres::PostgresConnection::default().await?;
        let chain_registrar = crate::node::DefaultChainRegistrar;

        handle_verification(
            text_content,
            redis_connection,
            &pg_conn,
            &chain_registrar,
            network,
            account_id,
            account,
        )
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AccountType, AccountVerification, ChallengeInfo};
    use context::mock::{MockChainRegistrar, MockTimelineStore, MockVerificationStore};
    use std::collections::HashMap;
    use std::str::FromStr;

    fn create_test_state(token: &str, done: bool) -> AccountVerification {
        let mut challenges = HashMap::new();
        challenges.insert(
            AccountType::Email,
            ChallengeInfo {
                account_name: "test@example.com".to_string(),
                done,
                token: Some(token.to_string()),
            },
        );
        AccountVerification {
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            network: "paseo".to_string(),
            challenges,
            completed: done,
        }
    }

    #[tokio::test]
    async fn test_handle_verification_success() {
        let network = Network::Paseo;
        let account_id = AccountId32::from_str("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let account = Account::Email("test@example.com".to_string());
        let token = "test-token-123";

        let mut verification_store = MockVerificationStore::new()
            .with_state(&network, &account_id, create_test_state(token, false));
        let timeline_store = MockTimelineStore::new();
        let chain_registrar = MockChainRegistrar::new();

        let result = handle_verification(
            token,
            &mut verification_store,
            &timeline_store,
            &chain_registrar,
            &network,
            &account_id,
            &account,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HandleResult::ChallengeVerified);

        // Verify challenge was updated
        let updated = verification_store.get_updated_challenges();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].2, AccountType::Email);

        // Verify timeline was updated
        let updates = timeline_store.get_updates();
        assert_eq!(updates.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_verification_wrong_token() {
        let network = Network::Paseo;
        let account_id = AccountId32::from_str("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let account = Account::Email("test@example.com".to_string());

        let mut verification_store = MockVerificationStore::new()
            .with_state(&network, &account_id, create_test_state("correct-token", false));
        let timeline_store = MockTimelineStore::new();
        let chain_registrar = MockChainRegistrar::new();

        let result = handle_verification(
            "wrong-token",
            &mut verification_store,
            &timeline_store,
            &chain_registrar,
            &network,
            &account_id,
            &account,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Wrong challenge"));
    }

    #[tokio::test]
    async fn test_handle_verification_no_state() {
        let network = Network::Paseo;
        let account_id = AccountId32::from_str("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let account = Account::Email("test@example.com".to_string());

        let mut verification_store = MockVerificationStore::new(); // no state added
        let timeline_store = MockTimelineStore::new();
        let chain_registrar = MockChainRegistrar::new();

        let result = handle_verification(
            "any-token",
            &mut verification_store,
            &timeline_store,
            &chain_registrar,
            &network,
            &account_id,
            &account,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Challenge does not exist"));
    }

    #[tokio::test]
    async fn test_handle_verification_already_done() {
        let network = Network::Paseo;
        let account_id = AccountId32::from_str("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
        let account = Account::Email("test@example.com".to_string());

        let mut verification_store = MockVerificationStore::new()
            .with_state(&network, &account_id, create_test_state("token", true)); // done = true
        let timeline_store = MockTimelineStore::new();
        let chain_registrar = MockChainRegistrar::new();

        let result = handle_verification(
            "token",
            &mut verification_store,
            &timeline_store,
            &chain_registrar,
            &network,
            &account_id,
            &account,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already register"));
    }
}
