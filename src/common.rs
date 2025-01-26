use anyhow::anyhow;
use serde::Deserialize;
use std::str::FromStr;
use subxt::utils::AccountId32;
use tracing::{debug, info};

use crate::{
    api::{Account, AccountType}, common, config::{RegistrarConfig, GLOBAL_CONFIG}, node::{
        runtime_types::{
            pallet_identity::types::{Data as IdentityData, Judgement, Registration},
            people_rococo_runtime::people::IdentityInfo,
        },
        Client as NodeClient,
    }
};

/// Checks if fee is paid
/// TODO: migrate this to a common module
pub fn has_paid_fee(judgements: Vec<(u32, Judgement<u128>)>) -> anyhow::Result<(), anyhow::Error> {
    if judgements
        .iter()
        .any(|(_, j)| matches!(j, Judgement::FeePaid(_)))
    {
        Ok(())
    } else {
        Err(anyhow!("fee is not paid!"))
    }
}

/// Compares between the accounts on the identity object
/// and the received requests
pub fn is_complete<'a>(
    registration: &Registration<u128, IdentityInfo>,
    expected: &Vec<Account>,
) -> anyhow::Result<(), anyhow::Error> {
    for acc in expected {
        let (stored_acc, expected_acc) = match acc {
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
            Account::Email(email_acc) => {
                (identity_data_tostring(&registration.info.email), email_acc)
            }
            _ => todo!(),
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

/// Converts the inner of [IdentityData] to a [String]
pub fn identity_data_tostring(data: &IdentityData) -> Option<String> {
    let result = match data {
        IdentityData::Raw0(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw1(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw2(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw3(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw4(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw5(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw6(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw7(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw8(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw9(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw10(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw11(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw12(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw13(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw14(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw15(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw16(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw17(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw18(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw19(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw20(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw21(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw22(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw23(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw24(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw25(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw26(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw27(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw28(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw29(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw30(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw31(v) => Some(String::from_utf8_lossy(v).to_string()),
        IdentityData::Raw32(v) => Some(String::from_utf8_lossy(v).to_string()),
        _ => None,
    };
    debug!("Data: {:?}", result);

    result
}

/// helper function to deserialize SS58 string into AccountId32
pub fn ss58_to_account_id32<'de, D>(deserializer: D) -> Result<AccountId32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ss58: String = Deserialize::deserialize(deserializer)?;
    AccountId32::from_str(&ss58)
        .map_err(|e| serde::de::Error::custom(format!("Invalid SS58: {e:?}")))
}

pub fn string_to_account_id(s: &str) -> anyhow::Result<AccountId32> {
    AccountId32::from_str(s).map_err(|e| anyhow!("Invalid account ID: {}", e))
}

/// Get the registration request object of `who` using the provided `client`
pub async fn get_registration(
    client: &super::node::Client,
    who: &AccountId32,
) -> anyhow::Result<Registration<u128, IdentityInfo>> {
    let storage = client.storage().at_latest().await?;
    let identity = super::node::storage().identity().identity_of(who);
    info!("identity: {:?}", identity);
    match storage.fetch(&identity).await? {
        None => Err(anyhow!("No registration found for {}", who)),
        Some((reg, _)) => Ok(reg),
    }
}

fn validate_account_types(
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

/// checks if the registration request is well formed (paid fee, accounts can be validated, etc)
pub async fn check_node(
    id: AccountId32,
    accounts: Vec<Account>,
    network: &str,
) -> anyhow::Result<()> {
    let cfg = GLOBAL_CONFIG
        .get()
        .expect("GLOBAL_CONFIG is not initialized");
    let network_cfg = cfg
        .registrar
        .get_network(network)
        .ok_or_else(|| anyhow!("Network {} not configured", network))?;

    let client = NodeClient::from_url(&network_cfg.endpoint).await?;
    let registration = common::get_registration(&client, &id).await?;

    info!("registration: {:#?}", registration);

    is_complete(&registration, &accounts)?;
    has_paid_fee(registration.judgements.0)?;
    validate_account_types(&accounts, network_cfg)?;

    Ok(())
}
