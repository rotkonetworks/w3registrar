//! WebSocket message types and request/response structures

#![allow(dead_code)]

use super::types::{ss58_to_account_id32, AccountType, Network};
use crate::postgres::{DisplayedInfo, SearchInfo};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubscribeAccountStateRequest {
    #[serde(rename = "type")]
    pub _type: RequestType,
    pub payload: AccountId32,
    pub network: Network,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyPGPKeyRequest {
    #[serde(rename = "type")]
    pub _type: RequestType,
    pub pubkey: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub network: Network,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingSubscribeRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingVerifyPGPRequest {
    pub network: Network,
    pub signed_challenge: String,
    pub pubkey: String,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingVerifyPGPAutomatedRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingUploadPGPKeyRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub armored_key: String,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingFetchPGPKeyRequest {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingUpdateRemailerSettingsRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub remailer_enabled: bool,
    pub remailer_registered_only: bool,
    pub require_verified_pgp: bool,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingSearchRequest {
    pub network: Option<Network>,
    pub outputs: Vec<DisplayedInfo>,
    pub filters: Filter,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IncomingAccountHistoryRequest {
    pub account: String,
    pub network: Option<Network>,
    pub limit: Option<i64>,
}

/// Block a sender from contacting you via remailer
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemailerBlockRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub blocked_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub signature: String,
    pub timestamp: u64,
}

/// Unblock a sender
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemailerUnblockRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub blocked_address: String,
    pub signature: String,
    pub timestamp: u64,
}

/// Get list of blocked senders
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemailerGetBlockedRequest {
    pub network: Network,
    #[serde(deserialize_with = "ss58_to_account_id32")]
    pub account: AccountId32,
    pub signature: String,
    pub timestamp: u64,
}

mod date_format {
    use chrono::NaiveDate;
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &str = "%Y-%m-%d";

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<NaiveDate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            Some(date_str) => NaiveDate::parse_from_str(&date_str, FORMAT)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }

    pub fn serialize<S>(date: &Option<NaiveDate>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(date) => serializer.serialize_str(&date.format(FORMAT).to_string()),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TimeFilter {
    #[serde(with = "date_format", default)]
    pub gt: Option<NaiveDate>,
    #[serde(with = "date_format", default)]
    pub lt: Option<NaiveDate>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Filter {
    pub fields: Vec<FieldsFilter>,
    pub result_size: Option<usize>,
    pub time: Option<TimeFilter>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FieldsFilter {
    pub field: SearchInfo,
    pub strict: bool,
}

impl FieldsFilter {
    pub fn new(field: SearchInfo, strict: bool) -> Self {
        Self { field, strict }
    }
}

impl Filter {
    pub fn new(
        fields: Vec<FieldsFilter>,
        result_size: Option<usize>,
        time: Option<TimeFilter>,
    ) -> Self {
        Self {
            fields,
            result_size,
            time,
        }
    }

    pub(crate) fn generic_search_fields(&self) -> Option<(String, bool)> {
        for field in self.fields.iter() {
            if let SearchInfo::Generic(value) = field.field.to_owned() {
                return Some((value, field.strict));
            }
        }
        None
    }
}

impl IncomingSearchRequest {
    pub fn new(network: Option<Network>, outputs: Vec<DisplayedInfo>, filters: Filter) -> Self {
        Self {
            network,
            outputs,
            filters,
        }
    }

    pub async fn search(self) -> anyhow::Result<Vec<crate::postgres::RegistrationRecord>> {
        use crate::postgres::{
            RegistrationCondition, RegistrationDisplayed, RegistrationQuery, SearchSpace,
            TimelineQuery,
        };

        if self.outputs.contains(&DisplayedInfo::Timeline) {
            let mut registration_query = RegistrationQuery::default();
            let displayed = RegistrationDisplayed::from(&self);
            let condition = RegistrationCondition::from(&self);
            let space = SearchSpace::construct_space(&self);

            registration_query = registration_query
                .selected(displayed)
                .condition(condition)
                .space(space);

            let mut registrations = registration_query.exec().await?;

            TimelineQuery::supply(
                &mut registrations,
                self.filters.result_size,
                self.filters.time,
            )
            .await?;

            Ok(registrations)
        } else {
            let mut registration_query = RegistrationQuery::default();
            let mut displayed = RegistrationDisplayed::default();
            let mut condition = RegistrationCondition::default();
            let space = SearchSpace::construct_space(&self);

            for filter in self.filters.fields.iter() {
                condition = condition.filter(filter);
            }

            if let Some(network) = self.network {
                condition = condition.network(&network);
            }

            for output in self.outputs {
                if let Ok(output) = output.try_into() {
                    displayed.push(output);
                }
            }

            if let Some(result_size) = self.filters.result_size {
                displayed = displayed.result_size(result_size);
            }

            registration_query = registration_query
                .selected(displayed)
                .condition(condition)
                .space(space);

            registration_query.exec().await
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengedAccount {
    pub network: String,
    pub account: String,
    pub field: AccountType,
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationRequest {
    #[serde(rename = "type")]
    pub _type: RequestVerificationChallenge,
    pub payload: RequestedAccount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestedAccount {
    pub wallet_id: AccountId32,
    pub field: AccountType,
    pub network: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationResponse {
    pub version: String,
    #[serde(rename = "type")]
    pub _type: RequestVerificationChallenge,
    payload: super::types::Account,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyIdentityRequest {
    #[serde(rename = "type")]
    pub _type: String,
    pub payload: ChallengedAccount,
}

/// Admin request to manually approve a verification challenge
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminApproveRequest {
    pub network: Network,
    pub account: AccountId32,
    pub account_type: AccountType,
    pub admin_account: AccountId32,
    pub signature: String,
    pub timestamp: u64,
}

/// Admin request to manually reject a verification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminRejectRequest {
    pub network: Network,
    pub account: AccountId32,
    pub reason: Option<String>,
    pub admin_account: AccountId32,
    pub signature: String,
    pub timestamp: u64,
}

/// Admin request to force provide judgement on-chain
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminProvideJudgementRequest {
    pub network: Network,
    pub account: AccountId32,
    pub admin_account: AccountId32,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum WebSocketMessage {
    SubscribeAccountState(IncomingSubscribeRequest),
    VerifyPGPKey(IncomingVerifyPGPRequest),
    VerifyPGPKeyAutomated(IncomingVerifyPGPAutomatedRequest),
    UploadPGPKey(IncomingUploadPGPKeyRequest),
    FetchPGPKey(IncomingFetchPGPKeyRequest),
    UpdateRemailerSettings(IncomingUpdateRemailerSettingsRequest),
    RemailerBlock(RemailerBlockRequest),
    RemailerUnblock(RemailerUnblockRequest),
    RemailerGetBlocked(RemailerGetBlockedRequest),
    SearchRegistration(IncomingSearchRequest),
    GetAccountHistory(IncomingAccountHistoryRequest),
    AdminApprove(AdminApproveRequest),
    AdminReject(AdminRejectRequest),
    AdminProvideJudgement(AdminProvideJudgementRequest),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionedMessage {
    pub version: String,
    #[serde(flatten)]
    pub payload: WebSocketMessage,
}

impl VersionedMessage {
    pub fn message_type_str(&self) -> &'static str {
        match self.payload {
            WebSocketMessage::SubscribeAccountState(_) => "SubscribeAccountState",
            WebSocketMessage::VerifyPGPKey(_) => "VerifyPGPKey",
            WebSocketMessage::VerifyPGPKeyAutomated(_) => "VerifyPGPKeyAutomated",
            WebSocketMessage::UploadPGPKey(_) => "UploadPGPKey",
            WebSocketMessage::FetchPGPKey(_) => "FetchPGPKey",
            WebSocketMessage::UpdateRemailerSettings(_) => "UpdateRemailerSettings",
            WebSocketMessage::RemailerBlock(_) => "RemailerBlock",
            WebSocketMessage::RemailerUnblock(_) => "RemailerUnblock",
            WebSocketMessage::RemailerGetBlocked(_) => "RemailerGetBlocked",
            WebSocketMessage::SearchRegistration(_) => "SearchRegistration",
            WebSocketMessage::GetAccountHistory(_) => "GetAccountHistory",
            WebSocketMessage::AdminApprove(_) => "AdminApprove",
            WebSocketMessage::AdminReject(_) => "AdminReject",
            WebSocketMessage::AdminProvideJudgement(_) => "AdminProvideJudgement",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SubscribeAccountState {
    SubscribeAccountState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RequestType {
    SubscribeAccountState,
    VerifyPGPKey,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RequestVerificationChallenge {
    RequestVerificationChallenge,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VerifyIdentity {
    VerifyIdentity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsonResultPayload {
    #[serde(rename = "type")]
    pub response_type: String,
    pub message: serde_json::Value,
}
