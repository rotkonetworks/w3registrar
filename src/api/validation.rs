use super::types::*;
use crate::config::{Config, RegistrarConfig};
use crate::node::{
    self,
    substrate::runtime_types::{
        pallet_identity::types::{Judgement, Registration},
        people_paseo_runtime::people::IdentityInfo,
    },
    Client as NodeClient,
};

use anyhow::anyhow;
use sp_core::blake2_256;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tracing::info;

pub async fn check_node(
    id: AccountId32,
    accounts: Vec<Account>,
    network: &Network,
) -> anyhow::Result<()> {
    let cfg = Config::load_static();
    let network_cfg = cfg.registrar.require_network(network)?;

    let client = NodeClient::from_url(&network_cfg.endpoint).await?;
    let registration = node::get_registration(&client, &id).await?;

    info!(registration = %format!("{:?}", registration));

    is_complete(&registration, &accounts)?;
    has_paid_fee(registration.judgements.0)?;
    validate_account_types(&accounts, network_cfg)?;

    Ok(())
}

pub fn validate_account_types(
    accounts: &[Account],
    network_cfg: &RegistrarConfig,
) -> anyhow::Result<()> {
    for account in accounts {
        let acc_type = account.account_type();
        let supported = network_cfg.fields.iter().any(|field| {
            AccountType::from_str(field)
                .map(|f| f == acc_type)
                .unwrap_or(false)
        });

        if !supported {
            return Err(anyhow!(
                "Account type {} is not supported on this network",
                acc_type,
            ));
        }
    }
    Ok(())
}

pub fn has_paid_fee(judgements: Vec<(u32, Judgement<u128>)>) -> anyhow::Result<()> {
    if judgements
        .iter()
        .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
    {
        Ok(())
    } else {
        Err(anyhow!("fee is not paid!"))
    }
}

pub fn is_complete(
    registration: &Registration<u128, IdentityInfo>,
    expected: &[Account],
) -> anyhow::Result<()> {
    for acc in expected {
        let (stored_acc, expected_acc) = match acc {
            Account::Email(email_acc) => {
                (identity_data_tostring(&registration.info.email), email_acc)
            }
            Account::Discord(discord_acc) => (
                identity_data_tostring(&registration.info.discord),
                discord_acc,
            ),
            Account::Display(display_name) => (
                identity_data_tostring(&registration.info.display),
                display_name,
            ),
            Account::Matrix(matrix_acc) => (
                identity_data_tostring(&registration.info.matrix),
                matrix_acc,
            ),
            Account::Twitter(twit_acc) => {
                (identity_data_tostring(&registration.info.twitter), twit_acc)
            }
            Account::Web(web_acc) => (identity_data_tostring(&registration.info.web), web_acc),
            Account::Github(github_acc) => (
                identity_data_tostring(&registration.info.github),
                github_acc,
            ),
            Account::Legal(_) => todo!(),
            Account::Image(image) => (identity_data_tostring(&registration.info.image), image),
            Account::PGPFingerprint(fingerprint) => (
                Some(hex::encode(
                    registration
                        .info
                        .pgp_fingerprint
                        .ok_or_else(|| anyhow!("Internal error"))?,
                )),
                &hex::encode(fingerprint),
            ),
        };

        let stored_acc = stored_acc.ok_or_else(|| {
            anyhow!(
                "{} acc {} not in identity obj",
                acc.account_type(),
                expected_acc
            )
        })?;

        if !expected_acc.eq(&stored_acc) {
            return Err(anyhow!("got {}, expected {}", expected_acc, stored_acc));
        }
    }
    Ok(())
}

pub fn hash_identity_info(info: &IdentityInfo) -> String {
    let info_bytes = parity_scale_codec::Encode::encode(info);
    let hash = blake2_256(&info_bytes);
    format!("0x{}", hex::encode(hash))
}

pub fn verify_timestamp(timestamp: u64) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let age_ms = now.saturating_sub(timestamp);
    const MAX_AGE_MS: u64 = 5 * 60 * 1000;

    if age_ms > MAX_AGE_MS {
        return Err(anyhow!(
            "Signature timestamp too old: {} ms (max {} ms)",
            age_ms,
            MAX_AGE_MS
        ));
    }
    Ok(())
}
