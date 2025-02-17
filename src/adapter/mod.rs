use subxt::utils::AccountId32;
use tracing::info;

use crate::{
    api::{Account, RedisConnection},
    node::register_identity,
};

pub mod dns;
pub mod mail;
pub mod matrix;

pub trait Adapter {
    async fn handle_content(
        text_content: &str,
        redis_connection: &mut RedisConnection,
        network: &str,
        account_id: &AccountId32,
        account: &Account,
    ) -> anyhow::Result<bool> {
        let account_type = &account.account_type().to_string();

        // get the current state
        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => return Ok(false),
        };

        // get the challenge for the account type
        let challenge = match state.challenges.get(account_type) {
            Some(challenge) => challenge,
            None => return Ok(false),
        };

        info!("Checking if all challenges are already done...");
        // challenge is already completed
        if challenge.done {
            return Ok(false);
        }

        // verify the token
        let token = match &challenge.token {
            Some(token) => token,
            None => return Ok(false),
        };

        // check if the message matches the token (fixed comparison)
        if text_content != *token {
            return Ok(false);
        }

        // update challenge status
        let result = redis_connection
            .update_challenge_status(network, account_id, account_type)
            .await?;

        let state = match redis_connection
            .get_verification_state(network, account_id)
            .await?
        {
            Some(state) => state,
            None => return Ok(false),
        };

        // register identity if all challenges are completed
        if state.all_done {
            register_identity(account_id, network).await?;
        }

        Ok(result)
    }
}
