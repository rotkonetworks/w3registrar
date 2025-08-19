#![allow(unused)]
// TODO: add table name for the queries?

use anyhow::anyhow;
use hex::ToHex;
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use postgres_types::{to_sql_checked, Kind, ToSql, Type};
use serde::{Deserialize, Serialize};
use sp_core::H256;
use std::any::Any;
use std::fmt::{format, Display};
use std::ops::Deref;
use std::slice::Iter;
use std::{str::FromStr, time::Duration};
use subxt::ext::codec::Encode;
use subxt::storage::{DefaultAddress, StorageKeyValuePair};
use subxt::utils::{AccountId32, Yes};
use tokio_postgres::types::FromSql;
use tokio_postgres::{Client, GenericClient, NoTls, SimpleQueryMessage, Statement, ToStatement};
use tracing::instrument;
use tracing::{error, info, info_span, Span};

use crate::api::TimeFilter;
use crate::{
    api::{
        identity_data_tostring, AccountType, FieldsFilter, Filter, IncomingSearchRequest, Network,
    },
    config::{PostgresConfig, GLOBAL_CONFIG},
    node::{
        self,
        identity::events::JudgementGiven,
        runtime_types::{
            pallet_identity::types::Registration, people_paseo_runtime::people::IdentityInfo,
        },
        Client as NodeClient,
    },
};

pub struct PostgresConnection {
    span: Span,
    client: Client,
}

impl PostgresConnection {
    /// Creates all necessary `types` to handle long term registration process
    async fn init_types(&mut self) -> anyhow::Result<()> {
        info!("Ceating `EVENT` enum type");

        let create_acctype_enum = "
DO $$
BEGIN
    IF NOT EXISTS ( SELECT 1 FROM pg_type WHERE typname='event' )
    THEN CREATE TYPE EVENT AS ENUM (
            'verified', 'created', 'discord', 'twitter', 'matrix',
            'email', 'display', 'github', 'legal', 'web', 'pgp_fingerprint'
    );
    END IF;
END
$$;";

        info!("QUERY");
        info!("{create_acctype_enum}");

        self.client.simple_query(create_acctype_enum).await?;
        info!("Enum type `EVENT` created");

        info!("Ceating `NETWORK` enum type");

        let create_network_enum = "
DO $$
BEGIN
    IF NOT EXISTS ( SELECT 1 from pg_type WHERE typname='network' )
    THEN CREATE TYPE NETWORK AS ENUM ('paseo', 'polkadot', 'kusama', 'rococo');
    END IF;
END
$$;";

        info!("QUERY");
        info!("{create_network_enum}");

        self.client.simple_query(create_network_enum).await?;

        info!("Enum type `NETWORK` created");

        Ok(())
    }

    /// Creates all necessary `tables` to handle long term registration process
    async fn init_tables(&mut self) -> anyhow::Result<()> {
        // TODO: parametarize table name?
        info!("Creating `registration` table");

        let create_reg_record = "CREATE TABLE IF NOT EXISTS registration (
            wallet_id       VARCHAR (48),
            network         NETWORK,
            discord         TEXT,
            twitter         TEXT,
            matrix          TEXT,
            email           TEXT,
            display_name    TEXT,
            github          TEXT,
            legal           TEXT,
            web             TEXT,
            pgp_fingerprint VARCHAR(40),
            PRIMARY KEY     (wallet_id, network)
        )";

        info!("QUERY");
        info!("{create_reg_record}");

        self.client.simple_query(create_reg_record).await?;
        info!("Table `registration` created");

        info!("Creating `timeline_elem` table");

        let create_timeline_elem = "CREATE TABLE IF NOT EXISTS timeline_elem (
            wallet_id       VARCHAR (48) NOT NULL,
            network         TEXT NOT NULL,
            event           EVENT NOT NULL,
            date            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY     (wallet_id, network, event)
        );";

        info!("QUERY");
        info!("{create_timeline_elem}");

        self.client.simple_query(create_timeline_elem).await?;

        info!("Table `timeline_elem` created");

        let create_indexer_state = "CREATE TABLE IF NOT EXISTS indexer_state (
            network          NETWORK PRIMARY KEY,
            last_block_index BIGINT NOT NULL DEFAULT 0,
            last_block_hash  VARCHAR(66) NOT NULL,
            updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );";

        info!("QUERY");
        info!("{create_indexer_state}");

        self.client.simple_query(create_indexer_state).await?;

        info!("Table `indexer_state` created");

        Ok(())
    }

    /// Initate/create all necessary `tables` and `types` to handle registrations
    #[instrument(skip_all, parent = &self.span)]
    pub async fn init(&mut self) -> anyhow::Result<()> {
        info!("Initiating postgess types");
        self.init_types().await?;
        info!("Initiating postgess tables");
        self.init_tables().await?;
        Ok(())
    }

    /// DELETES previously held timeline related to `wallet_id` and `network`
    /// then creates a new one
    #[instrument(skip_all, parent = &self.span)]
    pub async fn init_timeline(
        &self,
        wallet_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()> {
        info!(network=?network, wallet_id=?wallet_id.to_string(),"Initiating timeline info");
        self.delete_timelines(&wallet_id, &network).await?;
        self.update_timeline(TimelineEvent::Created, wallet_id, network)
            .await
    }

    /// Finalizes thimeline info related to `wallet_id` and `network`
    #[instrument(skip_all, parent = &self.span)]
    pub async fn finalize_timeline(
        &self,
        wallet_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()> {
        info!(network=?network, wallet_id=?wallet_id.to_string(),"Finalizing timeline");
        self.update_timeline(TimelineEvent::Verified, wallet_id, network)
            .await
    }

    /// Updates timeline info rlated to `wallet_id` and `network` by `event_info`
    #[instrument(skip_all, parent = &self.span)]
    pub async fn update_timeline(
        &self,
        event_info: TimelineEvent,
        wallet_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()> {
        info!(wallet_id=?wallet_id.to_string(), network=?network, event=?event_info, "Updating timeline info");

        self.client
            .query(
                "INSERT INTO timeline_elem (wallet_id, network, EVENT) VALUES ($1, $2, $3)",
                &[&wallet_id.to_string(), &network.to_string(), &event_info],
            )
            .await?;

        Ok(())
    }

    /// DELETES all timeline info related to `wallet_id` and `network` from DB
    #[instrument(skip_all, parent = &self.span)]
    pub async fn delete_timelines(
        &self,
        wallet_id: &AccountId32,
        network: &Network,
    ) -> anyhow::Result<()> {
        info!(wallet_id=?wallet_id.to_string(), network=?network,"Deleting timeline info");
        let condition = TimelineCondition::default()
            .network(network)
            .wallet_id(wallet_id.clone());
        let table_name = "timeline_elem".to_string();

        let delete_query = DeleteQuery::default()
            .table_name(table_name)
            .condition(condition);
        let params = delete_query.params();

        let query_params: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|v| v as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        info!(statement=?delete_query.statement(), params=?query_params.as_slice(), "Delete query");

        self.client
            .query(&delete_query.statement(), query_params.as_slice())
            .await?;

        Ok(())
    }

    pub async fn save_registration(&mut self, record: &RegistrationRecord) -> anyhow::Result<()> {
        info!(who = ?record.wallet_id(), "Writing record");
        let insert_reg_record = format!("
            INSERT INTO registration(wallet_id, discord, twitter, matrix, email, display_name, github, legal, web, pgp_fingerprint, network)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, '{}') 
            ON CONFLICT (wallet_id, network) DO UPDATE SET 
                discord = EXCLUDED.discord,
                twitter = EXCLUDED.twitter,
                matrix = EXCLUDED.matrix,
                email = EXCLUDED.email,
                display_name = EXCLUDED.display_name,
                github = EXCLUDED.github,
                legal = EXCLUDED.legal,
                web = EXCLUDED.web,
                pgp_fingerprint = EXCLUDED.pgp_fingerprint",
            record.network());

        info!(query=?insert_reg_record,"QUERY");
        info!(record = ?record);

        self.client
            .execute(
                &insert_reg_record,
                &[
                    &record.wallet_id(),
                    &record.discord(),
                    &record.twitter(),
                    &record.matrix(),
                    &record.email(),
                    &record.display(),
                    &record.github(),
                    &record.legal(),
                    &record.web(),
                    &record.pgp_fingerprint(),
                ],
            )
            .await?;
        info!("Record written successfully");

        Ok(())
    }

    pub async fn update_indexer_state(
        &self,
        network: &Network,
        hash: &H256,
        index: &i64,
    ) -> anyhow::Result<()> {
        // FIXME: update time should be also be changed

        let query = format!("INSERT INTO indexer_state (network, last_block_hash, last_block_index) VALUES ('{}',$1, $2) ON CONFLICT (network) DO UPDATE SET last_block_hash = EXCLUDED.last_block_hash, last_block_index = EXCLUDED.last_block_index ; ", network);

        let values: &[&(dyn ToSql + Sync)] = &[&hex::encode(hash.as_bytes()), &index];

        self.client.query(&query, values).await?;

        Ok(())
    }

    pub async fn search_registration_records(
        &mut self,
        search_query: &RegistrationQuery,
    ) -> anyhow::Result<Vec<RegistrationRecord>> {
        let params = search_query.params();

        let query_params: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|v| v as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        info!(statement=?search_query.statement(), params=?query_params.as_slice(), "Registration request");

        Ok(self
            .client
            .query(&search_query.statement(), query_params.as_slice())
            .await?
            .iter()
            .map(RegistrationRecord::from)
            .collect())
    }

    pub async fn search_timeline_records(
        &mut self,
        search_query: &TimelineQuery,
    ) -> anyhow::Result<Vec<TimelineRecord>> {
        let params = search_query.params();

        let query_params: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|v| v as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        info!(statement=?search_query.statement(), params=?query_params.as_slice(), "Timeline request");

        Ok(self
            .client
            .query(&search_query.statement(), query_params.as_slice())
            .await?
            .iter()
            .map(TimelineRecord::from)
            .collect())
    }

    pub async fn delete(&mut self, query: DeleteQuery<TimelineCondition>) -> anyhow::Result<()> {
        let params = query.params();

        let query_params: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|v| v as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        info!(statement=?query.statement(), params=?query_params.as_slice(), "Delete query");

        self.client
            .query(&query.statement(), query_params.as_slice())
            .await?;
        Ok(())
    }

    pub async fn new(cfg: &PostgresConfig) -> anyhow::Result<Self> {
        let mut conn_cfg = tokio_postgres::Config::new();
        // this is because we have incompatible types of 'connection' (tls vs raw)
        let client = match &cfg.cert_path {
            Some(path) => {
                let mut builder = SslConnector::builder(SslMethod::tls())?;
                builder.set_ca_file(path)?;
                let connector = MakeTlsConnector::new(builder.build());
                conn_cfg
                    .user(&cfg.user)
                    .host(&cfg.host)
                    .port(cfg.port)
                    .dbname(&cfg.dbname);

                if let Some(pwd) = &cfg.password {
                    conn_cfg.password(pwd);
                };

                if let Some(opts) = &cfg.options {
                    conn_cfg.options(opts);
                }

                if let Some(timeout) = cfg.timeout {
                    conn_cfg.connect_timeout(Duration::from_millis(timeout));
                }

                let (client, connection) = conn_cfg.connect(connector).await?;

                let _join_handle = tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!(error = ?e, "postgres connection error");
                    }
                });
                client
            }
            None => {
                conn_cfg
                    .user(&cfg.user)
                    .host(&cfg.host)
                    .port(cfg.port)
                    .dbname(&cfg.dbname);

                if let Some(pwd) = &cfg.password {
                    conn_cfg.password(pwd);
                };

                if let Some(opts) = &cfg.options {
                    conn_cfg.options(opts);
                }

                if let Some(timeout) = cfg.timeout {
                    conn_cfg.connect_timeout(Duration::from_millis(timeout));
                }

                let (client, connection) = conn_cfg.connect(NoTls).await?;

                let _join_handle = tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!(error = ?e, "postgres connection error");
                    }
                });
                client
            }
        };
        info!("New postgress connection established!");

        let span = info_span!("postgress_conn");

        Ok(Self { client, span })
    }

    pub async fn default() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG.get().unwrap();
        let pog_config = cfg.postgres.clone();
        PostgresConnection::new(&pog_config).await
    }

    pub async fn get_indexer_state(&self, network: &Network) -> anyhow::Result<IndexerState> {
        let query = format!("SELECT network::text, last_block_index, last_block_hash, updated_at FROM indexer_state WHERE network='{}'", network);
        let postgres_connection = PostgresConnection::default().await?;
        Ok(IndexerState::try_from(
            &self.client.query_one(&query, &[]).await?,
        )?)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TimelineRecord {
    pub event: TimelineEvent,
    // FIXME
    pub date: String,
    #[serde(skip_serializing)]
    pub wallet_id: AccountId32,
}

impl From<&tokio_postgres::Row> for TimelineRecord {
    fn from(value: &tokio_postgres::Row) -> Self {
        let date: chrono::NaiveDateTime = value.get("date");
        let event: TimelineEvent = value.get("event");
        let wid: String = value.get("wallet_id");

        // TODO: handle unwrap?
        let wallet_id: AccountId32 = AccountId32::from_str(&wid).unwrap();
        Self {
            event,
            date: date.to_string(),
            wallet_id,
        }
    }
}

impl TimelineRecord {}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct RegistrationRecord {
    // NOTE: should network and wallet_id bet Option?
    pub wallet_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub twitter: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub matrix: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgp_fingerprint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<Vec<TimelineRecord>>,
}

impl RegistrationRecord {
    pub fn from_registration(
        acc: &AccountId32,
        registration: &Registration<u128, IdentityInfo>,
        network: Option<Network>,
    ) -> Self {
        let pgp_fingerprint = match registration.info.pgp_fingerprint {
            Some(bytes) => Some(hex::encode(bytes)),
            None => None,
        };
        Self {
            network,
            wallet_id: acc.to_string(),
            discord: identity_data_tostring(&registration.info.discord),
            twitter: identity_data_tostring(&registration.info.twitter),
            matrix: identity_data_tostring(&registration.info.matrix),
            email: identity_data_tostring(&registration.info.email),
            display_name: identity_data_tostring(&registration.info.display),
            github: identity_data_tostring(&registration.info.github),
            legal: identity_data_tostring(&registration.info.legal),
            web: identity_data_tostring(&registration.info.web),
            pgp_fingerprint,
            timeline: None,
        }
    }

    pub async fn from_storage_pairs(
        pairs: &StorageKeyValuePair<
            DefaultAddress<(), Registration<u128, IdentityInfo>, (), (), Yes>,
        >,
        network: &Network,
    ) -> anyhow::Result<Option<Self>> {
        let key_bytes = &pairs.key_bytes;
        let account_bytes: [u8; 32] = key_bytes[key_bytes.len() - 32..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length for AccountId32"))?;

        let account_id = AccountId32::from(account_bytes);

        let pgp_fingerprint = match pairs.value.info.pgp_fingerprint {
            Some(bytes) => Some(hex::encode(bytes)),
            None => None,
        };

        Ok(Some(Self {
            network: Some(network.to_owned()),
            wallet_id: account_id.to_string().to_owned(),
            discord: identity_data_tostring(&pairs.value.info.discord),
            twitter: identity_data_tostring(&pairs.value.info.twitter),
            matrix: identity_data_tostring(&pairs.value.info.matrix),
            email: identity_data_tostring(&pairs.value.info.email),
            display_name: identity_data_tostring(&pairs.value.info.display),
            github: identity_data_tostring(&pairs.value.info.github),
            legal: identity_data_tostring(&pairs.value.info.legal),
            web: identity_data_tostring(&pairs.value.info.web),
            pgp_fingerprint,
            timeline: None,
        }))
    }

    // TODO: return None if judgement is not set correctly
    pub async fn from_judgement(jud: &JudgementGiven) -> anyhow::Result<Option<Self>> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let (network, reg_config) = match cfg.registrar.registrar_config(jud.registrar_index) {
            Some(v) => v,
            None => return Ok(None),
        };

        let client = NodeClient::from_url(&reg_config.endpoint).await?;
        let registration = node::get_registration(&client, &jud.target).await?;
        Ok(Some(Self::from_registration(
            &jud.target,
            &registration,
            Some(network),
        )))
    }

    pub fn wallet_id(&self) -> String {
        self.wallet_id.to_owned()
    }

    pub fn discord(&self) -> String {
        self.discord.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn twitter(&self) -> String {
        self.twitter.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn matrix(&self) -> String {
        self.matrix.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn email(&self) -> String {
        self.email.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn display(&self) -> String {
        self.display_name.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn github(&self) -> String {
        self.github.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn legal(&self) -> String {
        self.legal.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn web(&self) -> String {
        self.web.to_owned().unwrap_or("NULL".to_string())
    }

    pub fn pgp_fingerprint(&self) -> String {
        self.pgp_fingerprint
            .to_owned()
            .unwrap_or("NULL".to_string())
    }

    fn network(&self) -> String {
        format!("{}", self.network.clone().unwrap_or_default())
    }
}

impl From<&tokio_postgres::Row> for RegistrationRecord {
    fn from(value: &tokio_postgres::Row) -> Self {
        let mut record = RegistrationRecord::default();
        let displayed_info: Vec<DisplayedInfo> = value
            .columns()
            .iter()
            .filter_map(|v| DisplayedInfo::from_str(v.name()).ok())
            .collect();

        for info in displayed_info {
            match info {
                DisplayedInfo::WalletID => record.wallet_id = value.get("wallet_id"),
                DisplayedInfo::Network => record.network = value.get("network"),
                DisplayedInfo::Discord => record.discord = value.get("discord"),
                DisplayedInfo::Display => record.display_name = value.get("display_name"),
                DisplayedInfo::Email => record.email = value.get("email"),
                DisplayedInfo::Matrix => record.matrix = value.get("matrix"),
                DisplayedInfo::Twitter => record.twitter = value.get("twitter"),
                DisplayedInfo::Github => record.github = value.get("github"),
                DisplayedInfo::Legal => record.legal = value.get("legal"),
                DisplayedInfo::Web => record.web = value.get("web"),
                DisplayedInfo::PGPFingerprint => {
                    record.pgp_fingerprint = value.get("pgp_fingerprint")
                }
                // NOTE: This should not happen as [DisplayedInfo::from_str] never returns
                // [DisplayedInfo::Timeline]
                DisplayedInfo::Timeline => unreachable!(),
            }
        }

        return record;
    }
}

#[derive(Serialize, Deserialize)]
pub struct IndexerState {
    pub network: Network,
    pub last_block_index: i64,
    pub last_block_hash: H256,
    pub updated_at: chrono::NaiveDateTime,
}

impl IndexerState {
    pub fn init(network: Network) -> Self {
        Self {
            network,
            last_block_index: 0,
            last_block_hash: H256::default(),
            updated_at: chrono::NaiveDateTime::default(),
        }
    }
}

impl TryFrom<&tokio_postgres::Row> for IndexerState {
    type Error = anyhow::Error;

    fn try_from(value: &tokio_postgres::Row) -> Result<Self, Self::Error> {
        if value.is_empty() {
            error!("Rows are empty");
            return Err(anyhow!("Row is empty"));
        }

        let network: String = value.get("network");
        let last_block_hash: String = value.get("last_block_hash");
        let last_block_hash = H256::from_str(&last_block_hash)?;
        let last_block_index: i64 = value.get("last_block_index");
        let updated_at: chrono::NaiveDateTime = value.get("updated_at");
        info!(network=?network, last_block_index=?last_block_index, last_block_hash=?last_block_hash, last_update=?updated_at, "Indexing");
        let network = Network::from_str(&network)?;

        Ok(Self {
            network,
            last_block_index,
            last_block_hash,
            updated_at,
        })
    }
}

pub trait Query {
    type STATEMENT: ?Sized + ToStatement;
    type PARAM: ToSql + Sync;

    fn statement(&self) -> Self::STATEMENT;

    fn params(&self) -> Vec<Self::PARAM>;
}

/// Marker trait for all Condition like strucs
pub trait ConditionTrait {}

struct TimelineQueries {
    queries: Vec<TimelineQuery>,
}

pub struct TimelineQuery {
    pub condition: Option<TimelineCondition>,
    pub table_name: String,
    pub displayed: TimelineDisplayed,
    // TODO: add order
}

impl Default for TimelineQuery {
    fn default() -> Self {
        Self {
            displayed: TimelineDisplayed::default(),
            condition: None,
            table_name: "timeline_elem".to_string(),
        }
    }
}

// TODO: this query and impl Query for RegistrationQuery are identical,
// genaralize them somehow
impl Query for TimelineQuery {
    type STATEMENT = String;
    type PARAM = String;

    fn params(&self) -> Vec<String> {
        let mut thing = vec![];
        match &self.condition {
            Some(v) => {
                if let Some(wallet_id) = &v.wallet_id {
                    thing.push(wallet_id.to_string());
                }

                if let Some(date) = &v.date {
                    if let Some(lt) = date.lt {
                        thing.push(format!("{}", lt));
                    }

                    if let Some(gt) = date.gt {
                        thing.push(format!("{}", gt));
                    }
                }
            }
            None => {}
        }
        thing
    }

    fn statement(&self) -> String {
        let mut statement = String::from("SELECT ");

        if self.displayed.len() == 0 {
            statement.push_str("* ");
        } else {
            for (index, displayed) in self.displayed.iter().enumerate() {
                if index == 0 {
                    statement.push_str(&format!("{},", displayed.column_name()));
                } else {
                    statement.push_str(&format!(" {},", displayed.column_name()));
                }
            }
            statement = statement.trim_end_matches(|c| c == ',').to_owned();
        }

        statement.push_str(&format!(" FROM {} ", self.table_name));

        let mut index = 1;

        if let Some(v) = &self.condition {
            if !v.all_none() {
                statement.push_str("WHERE ");
                // naive approach
                if let Some(_) = &v.wallet_id {
                    statement.push_str(&format!("wallet_id = ${} AND ", index));
                    index += 1;
                }

                if let Some(date) = &v.date {
                    if let Some(_) = date.lt {
                        statement.push_str(&format!("date < ${} AND ", index));
                        index += 1;
                    }

                    if let Some(_) = date.gt {
                        statement.push_str(&format!("date > ${} AND", index));
                        index += 1;
                    }
                }

                if let Some(network) = &v.network {
                    statement.push_str(&format!("network = '{}' ", network));
                    index += 1;
                }

                statement = statement
                    .trim_end_matches(|c| c == ' ' || c == ',' || c == 'A' || c == 'N' || c == 'D')
                    .to_owned();
            }
        }

        statement
    }
}

impl TimelineQuery {
    /// supplies a [Vec<RegistrationRecord>] by [TimelineRecord]. This usually is done
    /// when a search request fields includes [DisplayedInfo::Timeline]
    pub async fn supply(
        rec: &mut Vec<RegistrationRecord>,
        size: Option<usize>,
        time: Option<TimeFilter>,
    ) -> anyhow::Result<()> {
        for record in rec.iter_mut() {
            let mut timeline_query = TimelineQuery::default();
            let mut condition = TimelineCondition::default();

            if let Some(network) = &record.network {
                condition = condition.network(&network);
            };

            if let Some(time) = &time {
                condition = condition.date(&time);
            }

            if let Ok(wallet_id) = AccountId32::from_str(&record.wallet_id.clone()) {
                condition = condition.wallet_id(wallet_id);
            }

            let selected = TimelineDisplayed::default().wallet_id().event().date();

            let mut timeline = timeline_query
                .selected(selected)
                .condition(condition)
                .exec()
                .await?;

            if let Some(size) = size {
                timeline.truncate(size);
            }

            record.timeline = Some(timeline);
        }
        Ok(())
    }

    pub async fn exec(&self) -> anyhow::Result<Vec<TimelineRecord>> {
        let mut pog_connection = PostgresConnection::default().await?;
        info!("Timeline search query");
        pog_connection.search_timeline_records(&self).await
    }

    pub fn derive_timeline_queries(
        rec: &Vec<RegistrationRecord>,
    ) -> Vec<(RegistrationRecord, TimelineQuery)> {
        let mut res = vec![];
        for record in rec.iter() {
            let mut timeline_query = TimelineQuery::default();
            let mut condition = TimelineCondition::default();

            if let Some(network) = &record.network {
                condition = condition.network(&network);
            };

            condition = condition.wallet_id(AccountId32::from_str(&record.wallet_id).unwrap());

            let selected = TimelineDisplayed::default().wallet_id().event().date();
            timeline_query = timeline_query.condition(condition).selected(selected);
            res.push((record.to_owned(), timeline_query));
        }
        res
    }
}

pub struct RegistrationQuery {
    pub displayed: RegistrationDisplayed,
    pub condition: Option<RegistrationCondition>,
    pub table_name: String,
    pub limit: Option<Limit>,
}

impl Default for RegistrationQuery {
    fn default() -> Self {
        Self {
            displayed: RegistrationDisplayed::default(),
            condition: None,
            limit: None,
            table_name: String::from("registration"),
        }
    }
}

impl Query for RegistrationQuery {
    type STATEMENT = String;

    type PARAM = String;

    fn statement(&self) -> Self::STATEMENT {
        let mut statement = String::from("SELECT ");

        if self.displayed.len() == 0 {
            statement.push_str("*");
        } else {
            for (index, displayed) in self.displayed.iter().enumerate() {
                if index == 0 {
                    statement.push_str(&format!("{},", displayed.table_field_name()));
                } else {
                    statement.push_str(&format!(" {},", displayed.table_field_name()));
                }
            }
            statement = statement.trim_end_matches(|c| c == ',').to_owned();
        }

        statement.push_str(" FROM registration ");
        let mut index_pointer = 1;

        match &self.condition {
            Some(v) => {
                if !v.filters.is_empty() || v.network.is_some() {
                    statement.push_str("WHERE ");
                }

                for (index, filter) in v.filters.iter().enumerate() {
                    if filter.strict {
                        statement.push_str(&format!(
                            "{} = ${}",
                            filter.field.table_column_name(),
                            index + 1
                        ));
                    } else {
                        statement.push_str(&format!(
                            "{} ILIKE ${}", // Postgres uses ILIKE for case-insensitive matching, 
                            //  LIKE is case-sensitive.
                            filter.field.table_column_name(),
                            index + 1
                        ));
                    }
                    index_pointer += 1;
                    statement.push_str(" AND ");
                }

                if let Some(network) = &v.network {
                    statement.push_str(&format!("network = '{}'", network));
                }

                statement = statement
                    .trim_end_matches(|c| c == ' ' || c == ',' || c == 'A' || c == 'N' || c == 'D')
                    .to_owned();
            }
            None => {}
        }

        if let Some(result_size) = self.displayed.result_size {
            statement.push_str(&format!(" LIMIT {}", result_size));
        }
        statement
    }

    fn params(&self) -> Vec<Self::PARAM> {
        let mut params = vec![];
        if let Some(condition) = &self.condition {
            for filter in condition.filters.iter() {
                params.push(format!("{}", if filter.strict {
                    filter.field.inner()    // exact match, e.g. display_name = 'Jow'
                } else {
                    format!("%{}%", filter.field.inner())   // e.g. display_name ILIKE '%Jow%'
                }));
            }
        }

        params
    }
}

impl RegistrationQuery {
    /// Executes the [RegistrationQuery]
    pub async fn exec(&self) -> anyhow::Result<Vec<RegistrationRecord>> {
        let mut pog_connection = PostgresConnection::default().await?;
        info!("Registration search query");
        pog_connection.search_registration_records(self).await
    }

    pub fn selected(mut self, displayed: RegistrationDisplayed) -> Self {
        self.displayed = displayed;
        self
    }

    pub fn condition(mut self, condition: RegistrationCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn limit(mut self, limit: Option<Limit>) -> Self {
        self.limit = limit;
        self
    }

    pub fn table_name(mut self, dbname: String) -> Self {
        self.table_name = dbname;
        self
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchResult {
    /// timeline record for each registreation
    pub result: Vec<RegistrationRecord>,
}

impl TimelineQuery {
    pub fn selected(mut self, displayed: TimelineDisplayed) -> Self {
        self.displayed = displayed;
        self
    }

    pub fn condition(mut self, condition: TimelineCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn table_name(mut self, dbname: String) -> Self {
        self.table_name = dbname;
        self
    }
}

#[derive(Debug)]
enum Order {
    ASC,
    DESC,
}

impl Display for Order {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default, Debug, Clone)]
pub struct Limit {
    size: usize,
}

impl Limit {
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

#[derive(Default, Debug)]
pub struct RegistrationCondition {
    filters: Vec<FieldsFilter>,
    network: Option<Network>,
}

impl From<&IncomingSearchRequest> for RegistrationCondition {
    fn from(value: &IncomingSearchRequest) -> Self {
        let mut condition = Self::default();
        for filter in value.filters.fields.iter() {
            condition = condition.filter(filter);
        }

        if let Some(network) = &value.network {
            condition = condition.network(&network);
        }
        condition
    }
}

impl RegistrationCondition {
    pub fn filter(mut self, filter: &FieldsFilter) -> RegistrationCondition {
        self.filters.push(filter.to_owned());
        self
    }

    pub fn network(mut self, network: &Network) -> RegistrationCondition {
        self.network = Some(network.to_owned());
        self
    }
}

#[derive(Default, Debug)]
pub struct TimelineCondition {
    date: Option<TimeFilter>,
    network: Option<Network>,
    wallet_id: Option<AccountId32>,
}

impl ConditionTrait for TimelineCondition {}

impl TimelineCondition {
    fn all_none(&self) -> bool {
        if self.date.is_some() {
            return false;
        }

        if self.network.is_some() {
            return false;
        }

        if self.wallet_id.is_some() {
            return false;
        }

        return true;
    }

    fn network(mut self, network: &Network) -> TimelineCondition {
        self.network = Some(network.to_owned());
        self
    }

    fn date(mut self, time: &TimeFilter) -> TimelineCondition {
        self.date = Some(time.to_owned());
        self
    }

    fn wallet_id(mut self, wallet_id: AccountId32) -> TimelineCondition {
        self.wallet_id = Some(wallet_id);
        self
    }
}

#[derive(Default)]
pub struct TimelineDisplayed {
    displayed: Vec<DisplayedTimelineInfo>,
}

impl TimelineDisplayed {
    fn len(&self) -> usize {
        self.displayed.len()
    }

    fn iter(&self) -> Iter<'_, DisplayedTimelineInfo> {
        self.displayed.iter()
    }

    fn wallet_id(mut self) -> Self {
        self.displayed.push(DisplayedTimelineInfo::WalletID);
        self
    }

    fn date(mut self) -> Self {
        self.displayed.push(DisplayedTimelineInfo::Date);
        self
    }

    fn event(mut self) -> Self {
        self.displayed.push(DisplayedTimelineInfo::Event);
        self
    }
}

#[derive(Default)]
pub struct RegistrationDisplayed {
    displayed: Vec<DisplayedRegistrationInfo>,
    result_size: Option<usize>,
}

impl From<&IncomingSearchRequest> for RegistrationDisplayed {
    fn from(value: &IncomingSearchRequest) -> Self {
        let mut displayed = RegistrationDisplayed::default();

        for output in value.outputs.iter() {
            let thing: Result<DisplayedRegistrationInfo, anyhow::Error> = output.try_into();
            if let Ok(output) = output.try_into() {
                displayed.push(output);
            }
        }

        if let Some(result_size) = value.filters.result_size {
            displayed = displayed.result_size(result_size);
        }
        displayed
    }
}

impl RegistrationDisplayed {
    pub fn iter(&self) -> Iter<'_, DisplayedRegistrationInfo> {
        self.displayed.iter()
    }

    pub fn push(&mut self, displayed: DisplayedRegistrationInfo) {
        self.displayed.push(displayed);
    }

    pub fn new(displayed: Vec<DisplayedRegistrationInfo>) -> Self {
        Self {
            displayed,
            result_size: None,
        }
    }

    pub fn displayed_info(self, output: &DisplayedInfo) -> RegistrationDisplayed {
        todo!()
        // self
    }

    fn len(&self) -> usize {
        self.displayed.len()
    }

    pub fn result_size(mut self, result_size: usize) -> RegistrationDisplayed {
        self.result_size = Some(result_size);
        self
    }
}

trait DisplayValidator {
    fn validate<T>(&self, t: T) -> Option<T>;
}

#[derive(Default)]
struct InsertFields {
    query: String,
}

// TODO: make inserting fields an enum :/
impl InsertFields {
    fn field(self, field_name: String) -> Self {
        self
    }
}

#[derive(Default)]
struct InsertValues {
    query: String,
}

impl InsertFields {
    fn value(self, field_value: String) -> Self {
        self
    }
}

#[derive(Default)]
pub struct DeleteQuery<T>
where
    T: Default + ConditionTrait,
{
    condition: Option<T>,
    table_name: String,
}

impl<T: Default + ConditionTrait> DeleteQuery<T> {
    pub fn table_name(mut self, table_name: String) -> Self {
        self.table_name = table_name;
        self
    }

    pub fn condition(mut self, condition: T) -> Self {
        self.condition = Some(condition);
        self
    }
}

impl Query for DeleteQuery<TimelineCondition> {
    type STATEMENT = String;

    type PARAM = String;

    fn statement(&self) -> Self::STATEMENT {
        let mut statement = format!("DELETE FROM {} ", self.table_name);
        let mut index = 1;

        if let Some(v) = &self.condition {
            if !v.all_none() {
                statement.push_str("WHERE ");
                if let Some(_) = &v.wallet_id {
                    statement.push_str(&format!("wallet_id = ${} AND ", index));
                    index += 1;
                }

                if let Some(date) = &v.date {
                    if let Some(_) = date.lt {
                        statement.push_str(&format!("date < ${} AND ", index));
                        index += 1;
                    }

                    if let Some(_) = date.gt {
                        statement.push_str(&format!("date > ${}", index));
                        index += 1;
                    }
                }

                if let Some(network) = &v.network {
                    statement.push_str(&format!("network = '{}'", network));
                    index += 1;
                }

                statement = statement
                    .trim_end_matches(|c| c == ' ' || c == ',' || c == 'A' || c == 'N' || c == 'D')
                    .to_owned();
            }
        }

        statement
    }

    fn params(&self) -> Vec<Self::PARAM> {
        let mut params = vec![];
        if let Some(v) = &self.condition {
            if !v.all_none() {
                if let Some(wallet_id) = &v.wallet_id {
                    params.push(format!("{}", wallet_id));
                }

                if let Some(network) = &v.network {
                    params.push(format!("{}", network));
                }

                if let Some(date) = &v.date {
                    if let Some(lt) = date.lt {
                        params.push(format!("{}", lt));
                    }

                    if let Some(gt) = date.gt {
                        params.push(format!("{}", gt));
                    }
                }
            }
        }
        params
    }
}

impl Query for String {
    type STATEMENT = String;

    type PARAM = String;

    fn statement(&self) -> Self::STATEMENT {
        self.clone()
    }

    fn params(&self) -> Vec<Self::PARAM> {
        vec![self.clone()]
    }
}

pub enum DisplayedTimelineInfo {
    WalletID,
    Event,
    Date,
    Network,
}

impl DisplayedTimelineInfo {
    fn column_name(&self) -> &str {
        match self {
            DisplayedTimelineInfo::WalletID => "wallet_id",
            DisplayedTimelineInfo::Event => "event",
            DisplayedTimelineInfo::Date => "date",
            DisplayedTimelineInfo::Network => "network",
        }
    }
}

pub enum DisplayedRegistrationInfo {
    WalletID,
    Discord,
    Display,
    Email,
    Matrix,
    Twitter,
    Github,
    Legal,
    Web,
    PGPFingerprint,
    Network,
}

impl DisplayedRegistrationInfo {
    fn table_field_name(&self) -> &'_ str {
        match self {
            DisplayedRegistrationInfo::WalletID => "wallet_id",
            DisplayedRegistrationInfo::Discord => "discord",
            DisplayedRegistrationInfo::Display => "display_name",
            DisplayedRegistrationInfo::Email => "email",
            DisplayedRegistrationInfo::Matrix => "matrix",
            DisplayedRegistrationInfo::Twitter => "twitter",
            DisplayedRegistrationInfo::Github => "github",
            DisplayedRegistrationInfo::Legal => "legal",
            DisplayedRegistrationInfo::Web => "web",
            DisplayedRegistrationInfo::PGPFingerprint => "pgp_fingerprint",
            DisplayedRegistrationInfo::Network => "network",
        }
    }
}

// TODO: add network for the displayed info
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy, Hash)]
pub enum DisplayedInfo {
    WalletID,
    Discord,
    Display,
    Email,
    Matrix,
    Twitter,
    Github,
    Legal,
    Web,
    PGPFingerprint,
    Timeline,
    Network,
}

impl TryInto<DisplayedRegistrationInfo> for DisplayedInfo {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<DisplayedRegistrationInfo, Self::Error> {
        match self {
            DisplayedInfo::WalletID => Ok(DisplayedRegistrationInfo::WalletID),
            DisplayedInfo::Network => Ok(DisplayedRegistrationInfo::Network),
            DisplayedInfo::Discord => Ok(DisplayedRegistrationInfo::Discord),
            DisplayedInfo::Display => Ok(DisplayedRegistrationInfo::Display),
            DisplayedInfo::Email => Ok(DisplayedRegistrationInfo::Email),
            DisplayedInfo::Matrix => Ok(DisplayedRegistrationInfo::Matrix),
            DisplayedInfo::Twitter => Ok(DisplayedRegistrationInfo::Twitter),
            DisplayedInfo::Github => Ok(DisplayedRegistrationInfo::Github),
            DisplayedInfo::Legal => Ok(DisplayedRegistrationInfo::Legal),
            DisplayedInfo::Web => Ok(DisplayedRegistrationInfo::Web),
            DisplayedInfo::PGPFingerprint => Ok(DisplayedRegistrationInfo::PGPFingerprint),
            DisplayedInfo::Timeline => Err(anyhow!(
                "Can't convert `DisplayedInfo::Timeline` to `DisplayedRegistrationInfo`"
            )),
        }
    }
}

impl TryInto<DisplayedRegistrationInfo> for &DisplayedInfo {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<DisplayedRegistrationInfo, Self::Error> {
        match self {
            DisplayedInfo::WalletID => Ok(DisplayedRegistrationInfo::WalletID),
            DisplayedInfo::Network => Ok(DisplayedRegistrationInfo::Network),
            DisplayedInfo::Discord => Ok(DisplayedRegistrationInfo::Discord),
            DisplayedInfo::Display => Ok(DisplayedRegistrationInfo::Display),
            DisplayedInfo::Email => Ok(DisplayedRegistrationInfo::Email),
            DisplayedInfo::Matrix => Ok(DisplayedRegistrationInfo::Matrix),
            DisplayedInfo::Twitter => Ok(DisplayedRegistrationInfo::Twitter),
            DisplayedInfo::Github => Ok(DisplayedRegistrationInfo::Github),
            DisplayedInfo::Legal => Ok(DisplayedRegistrationInfo::Legal),
            DisplayedInfo::Web => Ok(DisplayedRegistrationInfo::Web),
            DisplayedInfo::PGPFingerprint => Ok(DisplayedRegistrationInfo::PGPFingerprint),
            DisplayedInfo::Timeline => Err(anyhow!(
                "cannot convert `DisplayedInfo::Timeline` to `DisplayedRegistrationInfo`"
            )),
        }
    }
}

impl DisplayedInfo {
    #[allow(unused)]
    fn all_values() -> String {
        let v = vec![
            Self::WalletID,
            Self::Discord,
            Self::Display,
            Self::Email,
            Self::Matrix,
            Self::Twitter,
            Self::Github,
            Self::Legal,
            Self::Web,
            Self::PGPFingerprint,
            Self::Timeline,
        ];
        format!("{v:?}")
    }
}

impl FromStr for DisplayedInfo {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "wallet_id" | "WalletID" | "Wallet_ID" | "walletId" => return Ok(Self::WalletID),
            "Network" | "network" | "Network" => return Ok(Self::Network),
            "Discord" | "discord" => return Ok(Self::Discord),
            "Display" | "display" => return Ok(Self::Display),
            "Email" | "email" => return Ok(Self::Email),
            "Matrix" | "matrix" => return Ok(Self::Matrix),
            "Twitter" | "twitter" => return Ok(Self::Twitter),
            "Github" | "github" => return Ok(Self::Github),
            "Legal" | "legal" => return Ok(Self::Legal),
            "Web" | "web" => return Ok(Self::Web),
            "PGPFingerprint" | "pgpfingerprint" | "pgp_fingerprint" | "PGP_Fingerprint" => {
                return Ok(Self::PGPFingerprint)
            }
            // TODO: update this to include Date, Wallet ID and Event
            _ => return Err(anyhow!("Unknown type {s}")),
        }
    }
}

// TODO: switch to str instead of String :)
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchInfo {
    AccountId32(String),
    Twitter(String),
    Discord(String),
    Matrix(String),
    Display(String),
    Legal(String),
    Web(String),
    Email(String),
    Github(String),
    PGPFingerprint([u8; 20]),
}

impl SearchInfo {
    pub fn table_column_name(&self) -> &'_ str {
        match self {
            SearchInfo::AccountId32(_) => "wallet_id",
            SearchInfo::Twitter(_) => "twitter",
            SearchInfo::Discord(_) => "discord",
            SearchInfo::Matrix(_) => "matrix",
            SearchInfo::Display(_) => "display_name",
            SearchInfo::Legal(_) => "legal",
            SearchInfo::Web(_) => "web",
            SearchInfo::Email(_) => "email",
            SearchInfo::Github(_) => "github",
            SearchInfo::PGPFingerprint(_) => "pgp_fingerprint",
        }
    }

    pub fn inner(&self) -> String {
        match self {
            SearchInfo::AccountId32(inner)
            | SearchInfo::Twitter(inner)
            | SearchInfo::Discord(inner)
            | SearchInfo::Matrix(inner)
            | SearchInfo::Display(inner)
            | SearchInfo::Legal(inner)
            | SearchInfo::Web(inner)
            | SearchInfo::Email(inner)
            | SearchInfo::Github(inner) => inner.to_owned(),
            SearchInfo::PGPFingerprint(inner) => hex::encode(inner),
        }
    }
}

#[derive(Debug, Clone, ToSql, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[postgres(name = "event")]
pub enum TimelineEvent {
    #[postgres(name = "created")]
    #[serde(alias = "created")]
    Created,
    #[postgres(name = "verified")]
    #[serde(alias = "verified")]
    Verified,
    #[postgres(name = "discord")]
    #[serde(alias = "discord")]
    Discord,
    #[postgres(name = "display")]
    #[serde(alias = "display_name")]
    Display,
    #[postgres(name = "email")]
    #[serde(alias = "email")]
    Email,
    #[postgres(name = "matrix")]
    #[serde(alias = "matrix")]
    Matrix,
    #[postgres(name = "twitter")]
    #[serde(alias = "twitter")]
    Twitter,
    #[postgres(name = "github")]
    #[serde(alias = "github")]
    Github,
    #[postgres(name = "legal")]
    #[serde(alias = "legal")]
    Legal,
    #[postgres(name = "web")]
    #[serde(alias = "web")]
    Web,
    #[postgres(name = "image")]
    #[serde(alias = "image")]
    Image,
    #[postgres(name = "pgp_fingerprint")]
    #[serde(alias = "pgp_fingerprint")]
    PGPFingerprint,
}

impl<'a> FromSql<'a> for TimelineEvent {
    fn from_sql(
        ty: &postgres_types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let mut v = vec![];
        v.push(34);
        v.extend_from_slice(raw);
        v.push(34);
        if ty.name().to_lowercase() == "event" {
            let res: TimelineEvent = serde_json::from_slice(&v)?;
            return Ok(res);
        };

        return Err(anyhow!("error {:?} raw {:?}", ty, v).into());
    }

    fn accepts(ty: &postgres_types::Type) -> bool {
        ty.name().to_lowercase() == "event"
    }
}

impl From<&AccountType> for TimelineEvent {
    fn from(value: &AccountType) -> Self {
        match value {
            AccountType::Image => Self::Image,
            AccountType::Discord => Self::Discord,
            AccountType::Display => Self::Display,
            AccountType::Email => Self::Email,
            AccountType::Matrix => Self::Matrix,
            AccountType::Twitter => Self::Twitter,
            AccountType::Github => Self::Github,
            AccountType::Legal => Self::Legal,
            AccountType::Web => Self::Web,
            AccountType::PGPFingerprint => Self::PGPFingerprint,
        }
    }
}

impl Display for TimelineEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:#?}", self).to_lowercase())
    }
}

mod test {
    use chrono::{NaiveDate, NaiveDateTime};

    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn from_search_request() {
        let network: Option<Network> = Some(Network::Rococo);
        let outputs: Vec<DisplayedInfo> = vec![DisplayedInfo::WalletID, DisplayedInfo::Display];
        let filters: Filter = Filter::new(
            vec![
                FieldsFilter::new(SearchInfo::Display("Travis Hernandez".to_string()), false),
                FieldsFilter::new(SearchInfo::Discord("Travis Hernandez".to_string()), true),
            ],
            Some(2),
            None,
        );

        let search_req = IncomingSearchRequest::new(network, outputs.clone(), filters.clone());

        let mut displayed = RegistrationDisplayed::from(&search_req);
        let mut condition = RegistrationCondition::from(&search_req);
        let reg_query = RegistrationQuery::default()
            .selected(displayed)
            .condition(condition);

        assert_eq!(
            reg_query.statement(),
            "SELECT wallet_id, display_name FROM registration WHERE display LIKE $1 AND discord = $2 AND network = $3 LIMIT 2"
        );
        //  ------------------------------------------------------------------------------
        let network: Option<Network> = None;
        let filters: Filter = Filter::new(
            vec![FieldsFilter::new(
                SearchInfo::Display("Travis Hernandez".to_string()),
                true,
            )],
            Some(2),
            None,
        );

        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let mut displayed = RegistrationDisplayed::from(&search_req);
        let mut condition = RegistrationCondition::from(&search_req);
        let reg_query = RegistrationQuery::default()
            .selected(displayed)
            .condition(condition);

        assert_eq!(
            reg_query.statement(),
            "SELECT wallet_id, display_name FROM registration WHERE display = $1 LIMIT 2"
        );
        //  ------------------------------------------------------------------------------
        let outputs: Vec<DisplayedInfo> = vec![];
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let mut displayed = RegistrationDisplayed::from(&search_req);
        let mut condition = RegistrationCondition::from(&search_req);
        let reg_query = RegistrationQuery::default()
            .selected(displayed)
            .condition(condition);

        assert_eq!(
            reg_query.statement(),
            "SELECT * FROM registration WHERE display = $1 LIMIT 2"
        );
        //  ------------------------------------------------------------------------------
        let filters: Filter = Filter::default();
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let mut displayed = RegistrationDisplayed::from(&search_req);
        let mut condition = RegistrationCondition::from(&search_req);
        let reg_query = RegistrationQuery::default()
            .selected(displayed)
            .condition(condition);

        assert_eq!(reg_query.statement(), "SELECT * FROM registration");
    }

    #[test]
    fn search_registration_records() {
        let selected = RegistrationDisplayed::new(vec![
            DisplayedRegistrationInfo::WalletID,
            DisplayedRegistrationInfo::Discord,
        ]);

        let mut condition = RegistrationCondition::default()
            .network(&Network::Paseo)
            .filter(&FieldsFilter::new(
                SearchInfo::Email("thing@example.com".to_string()),
                false,
            ));
        let query = RegistrationQuery::default()
            .selected(selected)
            .condition(condition);

        assert_eq!(
            "SELECT wallet_id, discord FROM registration WHERE email LIKE $1 AND network = $2",
            query.statement()
        );
        assert_eq!(
            vec!["thing@example.com".to_string(), "paseo".to_string(),],
            query.params()
        );
    }

    #[test]
    fn search_by_date() {
        let selected = TimelineDisplayed::default().wallet_id().event().date();

        let date = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
        let time_filter = TimeFilter {
            gt: Some(date),
            lt: None,
        };

        let mut condition = TimelineCondition::default().network(&Network::Paseo);

        let mut timeline_query = TimelineQuery::default()
            .selected(selected)
            .condition(condition);

        let statement = timeline_query.statement();
        let params = timeline_query.params();
        assert_eq!(
            statement,
            "SELECT wallet_id, event, date FROM timeline_elem WHERE network = $1"
        );
        assert_eq!(params, vec!["paseo".to_string()]);
    }

    #[test]
    fn delete_query() {
        let mut condition = TimelineCondition::default()
            .network(&Network::Paseo)
            .wallet_id(
                AccountId32::from_str("5HmLjPdzJQHopPiyz3fF4M4fW3M5EV19sPZUqWRhwA91NPzT").unwrap(),
            );
        let table_name = String::from("registration");

        let delete_query = DeleteQuery::default()
            .condition(condition)
            .table_name(table_name);

        assert_eq!(
            "DELETE * FROM registration WHERE wallet_id = $1 AND network = $2",
            delete_query.statement()
        );

        assert_eq!(
            vec!["5HmLjPdzJQHopPiyz3fF4M4fW3M5EV19sPZUqWRhwA91NPzT", "paseo"],
            delete_query.params()
        )
    }
}
