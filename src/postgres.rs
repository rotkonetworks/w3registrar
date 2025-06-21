#![allow(unused)]
// TODO: add table name for the queries?

use anyhow::anyhow;
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::{str::FromStr, time::Duration};
use subxt::utils::AccountId32;
use tokio_postgres::types::FromSql;
use tokio_postgres::{Client, NoTls};
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

        info!("QUERRY");
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

        info!("QUERRY");
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
            pgp_fingerprint VARCHAR (20),
            PRIMARY KEY     (wallet_id, network)
        )";

        info!("QUERRY");
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

        info!("QUERRY");
        info!("{create_timeline_elem}");

        self.client.simple_query(create_timeline_elem).await?;

        info!("Table `registration` created");

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
        let insert_timeline = format!(
            "INSERT INTO timeline_elem (wallet_id, network, EVENT) VALUES ('{}', '{}', '{}')",
            &wallet_id.to_string(),
            &network.to_string(),
            &event_info,
        );
        info!("QUERRY: {insert_timeline}");

        self.client.simple_query(&insert_timeline).await?;
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
        let condition = Condition::default()
            .network(network)
            .and()
            .condition(&SearchInfo::AccountId32(wallet_id.to_string()));
        let table_name = "timeline_elem".to_string();

        let delete_query = DeleteQuery::default()
            .table_name(table_name)
            .condition(condition);

        self.client.simple_query(&delete_query.to_sql()).await?;
        Ok(())
    }

    pub async fn write(&mut self, record: &RegistrationRecord) -> anyhow::Result<()> {
        info!(who = ?record.wallet_id(), "Writing record");
        // TODO: write this programatically so we don't end with the NULL junk
        let insert_reg_record =
            "INSERT INTO registration(wallet_id, network, discord, twitter, matrix, email, display_name, github, legal, web, pgp_fingerprint)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        info!(query=?insert_reg_record,"QUERRY");
        info!(record = ?record);

        self.client
            .execute(
                insert_reg_record,
                &[
                    &record.wallet_id(),
                    &record.network(),
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

    pub async fn search_registration_records<Q>(
        &mut self,
        search_querry: Q,
    ) -> anyhow::Result<Vec<RegistrationRecord>>
    where
        Q: Query,
    {
        Ok(self
            .client
            .query(&search_querry.to_sql(), &[])
            .await?
            .iter()
            .map(RegistrationRecord::from)
            .collect())
    }

    pub async fn search_timeline_records<Q>(
        &mut self,
        search_querry: Q,
    ) -> anyhow::Result<Vec<TimelineRecord>>
    where
        Q: Query,
    {
        Ok(self
            .client
            .query(&search_querry.to_sql(), &[])
            .await?
            .iter()
            .map(TimelineRecord::from)
            .collect())
    }

    pub async fn delete<Q>(&mut self, query: Q) -> anyhow::Result<()>
    where
        Q: Query,
    {
        self.client.simple_query(&query.to_sql()).await?;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,

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
            wallet_id: Some(acc.to_string()),
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
        self.wallet_id.to_owned().unwrap_or("NULL".to_string())
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
                DisplayedInfo::Discord => record.discord = value.get("discord"),
                DisplayedInfo::Display => record.display_name = value.get("display"),
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

pub trait Query {
    // TODO
    // fn to_sql<Q>(&self) -> Q
    // where
    //     Q: Query;
    fn to_sql(&self) -> String;
}

struct TimelineQueries {
    queries: Vec<TimelineQuery>,
}

pub struct TimelineQuery {
    pub condition: Option<Condition>,
    pub table_name: String,
    pub displayed: Displayed,
    // TODO: add order
}

impl Default for TimelineQuery {
    fn default() -> Self {
        Self {
            displayed: Displayed::default(),
            condition: None,
            table_name: String::from("timeline_elem"),
        }
    }
}

// TODO: this querry and impl Query for RegistrationQuery are identical,
// genaralize them somehow
impl Query for TimelineQuery {
    fn to_sql(&self) -> String {
        let displayed = self.displayed.to_sql();
        let mut query = format!("SELECT {} FROM {}", displayed, self.table_name);

        match &self.condition {
            Some(condition) => query.push_str(&format!(" {}", condition.to_sql())),
            None => {}
        }
        query
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
            let mut condition = Condition::default();

            if let Some(network) = &record.network {
                condition = condition.network(&network);
            };

            if let Some(time) = &time {
                condition = condition.date(&time);
            }

            if let Some(wallet_id) = &record.wallet_id {
                condition = condition.condition(&SearchInfo::AccountId32(wallet_id.clone()));
            };

            let selected = Displayed::default().wallet_id().event().date();
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
        info!(query=?self.to_sql(), "Timelines search query");
        pog_connection.search_timeline_records(self.to_sql()).await
    }

    pub fn derive_timeline_queries(
        rec: &Vec<RegistrationRecord>,
    ) -> Vec<(RegistrationRecord, TimelineQuery)> {
        let mut res = vec![];
        for record in rec.iter() {
            let mut timeline_query = TimelineQuery::default();
            let mut condition = Condition::default();
            if let Some(network) = &record.network {
                condition = condition.network(&network);
            };

            if let Some(wallet_id) = &record.wallet_id {
                // FIXME
                condition = condition.wallet_id(&AccountId32::from_str(&wallet_id).unwrap());
            };

            let selected = Displayed::default().wallet_id().event().date();
            timeline_query = timeline_query.condition(condition).selected(selected);
            res.push((record.to_owned(), timeline_query));
        }
        res
    }
}

pub struct RegistrationQuery {
    pub displayed: Displayed,
    pub condition: Option<Condition>,
    pub table_name: String,
    pub limit: Option<Limit>,
}

impl Default for RegistrationQuery {
    fn default() -> Self {
        Self {
            displayed: Displayed::default(),
            condition: None,
            limit: None,
            table_name: String::from("registration"),
        }
    }
}

impl Query for RegistrationQuery {
    fn to_sql(&self) -> String {
        let displayed = self.displayed.to_sql();
        let mut query = format!("SELECT {} FROM {}", displayed, self.table_name);

        match &self.condition {
            Some(condition) => query.push_str(&format!(" {}", condition.to_sql())),
            None => {}
        };
        query
    }
}

impl RegistrationQuery {
    /// Executes the [RegistrationQuery]
    pub async fn exec(&self) -> anyhow::Result<Vec<RegistrationRecord>> {
        let mut pog_connection = PostgresConnection::default().await?;
        info!(query=?self.to_sql(), "Registration search query");
        pog_connection
            .search_registration_records(self.to_sql())
            .await
    }

    pub fn selected(mut self, displayed: Displayed) -> Self {
        self.displayed = displayed;
        self
    }

    pub fn condition(mut self, condition: Condition) -> Self {
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

#[derive(Default)]
/// General search query. Should be constructed from a SearchRequest
pub struct SimpleSearchQuery {
    pub table_name: String,
    pub displayed: Displayed,
    pub condition: Option<Condition>,
    pub limit: Option<Limit>,
}

impl SimpleSearchQuery {
    pub fn selected(mut self, displayed: Displayed) -> Self {
        self.displayed = displayed;
        self
    }

    pub fn condition(mut self, condition: Condition) -> Self {
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

impl TimelineQuery {
    pub fn selected(mut self, displayed: Displayed) -> Self {
        self.displayed = displayed;
        self
    }

    pub fn condition(mut self, condition: Condition) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn table_name(mut self, dbname: String) -> Self {
        self.table_name = dbname;
        self
    }
}

impl SimpleSearchQuery {
    // pub fn timeline(mut self, timeline: TimelineQuery) -> Self {
    //     self.timeline = Some(timeline);
    //     self
    // }
    // pub fn registration(mut self, registration: RegistrationQuery) -> Self {
    //     self.registration = Some(registration);
    //     self
    // }
    // pub fn limit(mut self, limit: Option<Limit>) -> Self {
    //     self.registration.as_mut().map(|v| v.limit = limit.clone());
    //     self.timeline.as_mut().map(|v| v.limit = limit);
    //     self
    // }
}

impl Query for SimpleSearchQuery {
    fn to_sql(&self) -> String {
        let mut query = format!("SELECT {}", self.displayed.to_sql());
        if let Some(cond) = &self.condition {
            query.push_str(&cond.to_sql());
        };

        if let Some(limit) = &self.limit {
            query.push_str(&limit.to_sql());
        };
        query
    }
}

impl SimpleSearchQuery {
    pub async fn exec(&self) -> anyhow::Result<Vec<RegistrationRecord>> {
        // if self.displayed.contains(&DisplayedInfo::Timeline) {
        //     // phase 1
        //     // phase 2
        //     // phase 3
        // } else {
        //     // phase 2
        // }
        // let mut pog_connection = PostgresConnection::default().await?;
        // info!(query=?self.to_sql(), "search query");
        // pog_connection.search(self.to_sql()).await
        // match &self.timeline {
        //     Some(query) => {
        //         info!(query=?query.to_sql(), "SEARCH QUERY");
        //         let res = pog_connection.search(query.to_sql()).await?;
        //     }
        //     None => {}
        // };
        //
        // match &self.registration {
        //     Some(query) => {
        //         info!(query=?query.to_sql(), "SEARCH QUERY");
        //         let res = pog_connection.search(query.to_sql()).await?;
        //     }
        //     None => {}
        // }
        todo!()
    }
}

#[derive(Debug)]
enum JoinType {
    INNER,
}

impl Display for JoinType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
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
    querry: usize,
}

impl Query for Limit {
    fn to_sql(&self) -> String {
        format!("LIMIT {}", self.querry)
    }
}

impl Limit {
    pub fn new(querry: usize) -> Self {
        Self { querry }
    }
}

#[derive(Default, Debug)]
pub struct Condition {
    querry: String,
    prefix: Option<String>,
}

// TODO: this api allows for .and().and() or .or().or() or even .account().account() which should
// not happen, my thoughts is that this should be wrapped with a builder
impl Condition {
    pub fn and(mut self) -> Self {
        self.querry.push_str("AND ");
        self
    }

    pub fn or(mut self) -> Self {
        self.querry.push_str("OR ");
        self
    }

    pub fn like_condition(mut self, account: &SearchInfo) -> Self {
        let query = match account {
            SearchInfo::AccountId32(info) => format!("wallet_id LIKE '%{}%' ", info),
            SearchInfo::Twitter(account) => format!("twitter LIKE '%{}%' ", account),
            SearchInfo::Discord(account) => format!("discord LIKE '%{}%' ", account),
            SearchInfo::Matrix(account) => format!("matrix LIKE '%{}%' ", account),
            SearchInfo::Display(account) => format!("display LIKE '%{}%' ", account),
            SearchInfo::Legal(account) => format!("legal LIKE '%{}%' ", account),
            SearchInfo::Web(account) => format!("web LIKE '%{}%' ", account),
            SearchInfo::Email(account) => format!("email LIKE '%{}%' ", account),
            SearchInfo::Github(account) => format!("github LIKE '%{}%' ", account),
            SearchInfo::PGPFingerprint(bytes) => {
                format!("pgp_fingerprint LIKE '%{}%' ", hex::encode(bytes))
            }
        };
        self.querry.push_str(&query);
        self
    }

    pub fn condition(mut self, info: &SearchInfo) -> Self {
        let query = match info {
            SearchInfo::AccountId32(info) => format!("wallet_id='{}' ", info),
            SearchInfo::Twitter(account) => format!("twitter='{}' ", account),
            SearchInfo::Discord(account) => format!("discord='{}' ", account),
            SearchInfo::Matrix(account) => format!("matrix='{}' ", account),
            SearchInfo::Display(account) => format!("display='{}' ", account),
            SearchInfo::Legal(account) => format!("legal='{}' ", account),
            SearchInfo::Web(account) => format!("web='{}' ", account),
            SearchInfo::Email(account) => format!("email='{}' ", account),
            SearchInfo::Github(account) => format!("github='{}' ", account),
            SearchInfo::PGPFingerprint(bytes) => {
                format!(" pgp_fingerprint='{}' ", hex::encode(bytes))
            }
        };
        self.querry.push_str(&query);
        self
    }

    pub fn network(mut self, network: &Network) -> Self {
        self.querry.push_str(&format!("network='{}' ", network));
        self.and()
    }

    pub fn wallet_id(mut self, wallet_id: &AccountId32) -> Self {
        self.querry.push_str(&wallet_id.to_string());
        self
    }

    pub fn wallet_id_str(mut self, wallet_id: &String) -> Self {
        self.querry.push_str(&wallet_id);
        self
    }

    pub fn filter(mut self, filter: &FieldsFilter) -> Self {
        if filter.strict {
            self = self.condition(&filter.field).and();
        } else {
            self = self.like_condition(&filter.field).and();
        }
        self
    }

    pub fn gt_date(mut self, gt: Option<chrono::NaiveDate>) -> Self {
        if let Some(time) = gt {
            self.querry.push_str(&format!("date > '{}'", time));
        }
        self
    }

    pub fn lt_date(mut self, lt: Option<chrono::NaiveDate>) -> Self {
        if let Some(time) = lt {
            self.querry.push_str(&format!("date < '{}'", time));
        }
        self
    }

    pub fn date(mut self, time: &TimeFilter) -> Self {
        if time.gt.is_some() {
            self = self.gt_date(time.gt).and()
        };
        if time.lt.is_some() {
            self = self.lt_date(time.lt).and();
        }
        self
    }
}

impl FromStr for Condition {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            querry: s.to_owned(),
            prefix: None,
        })
    }
}

impl Query for Condition {
    fn to_sql(&self) -> String {
        if self.querry.is_empty() {
            return String::new();
        } else {
            format!(
                "WHERE {}",
                self.querry.trim_end_matches(|c| c == ' '
                    || c == ','
                    || c == 'A'
                    || c == 'N'
                    || c == 'D')
            )
        }
    }
}

#[derive(Default)]
pub struct Displayed {
    querry: String,
}

trait DisplayValidator {
    fn validate<T>(&self, t: T) -> Option<T>;
}

impl Displayed {
    pub fn displayed_info(mut self, displayed_info: &DisplayedInfo) -> Self {
        match displayed_info {
            DisplayedInfo::WalletID => self.querry.push_str("wallet_id, "),
            DisplayedInfo::Discord => self.querry.push_str("discord, "),
            DisplayedInfo::Display => self.querry.push_str("display, "),
            DisplayedInfo::Email => self.querry.push_str("email, "),
            DisplayedInfo::Matrix => self.querry.push_str("matrix, "),
            DisplayedInfo::Twitter => self.querry.push_str("twitter, "),
            DisplayedInfo::Github => self.querry.push_str("github, "),
            DisplayedInfo::Legal => self.querry.push_str("legal, "),
            DisplayedInfo::Web => self.querry.push_str("web, "),
            DisplayedInfo::PGPFingerprint => self.querry.push_str("pgp_fingerprint, "),
            DisplayedInfo::Timeline => {
                info!("Ignoring field [DisplayedInfo::Timeline]...");
                // check [Self::date] and [Self::event]
            }
        }

        self
    }

    pub fn wallet_id(mut self) -> Self {
        self.querry.push_str("wallet_id, ");
        self
    }

    pub fn account(mut self, account: AccountType) -> Self {
        let query = match account {
            AccountType::Twitter => format!("twitter, "),
            AccountType::Discord => format!("discord, "),
            AccountType::Matrix => format!("matrix, "),
            AccountType::Display => format!("display_name, "),
            AccountType::Legal => format!("legal, "),
            AccountType::Web => format!("web, "),
            AccountType::Email => format!("email, "),
            AccountType::Github => format!("github, "),
            AccountType::PGPFingerprint => format!("pgp_fingerprint, "),
        };

        self.querry.push_str(&query);
        self
    }

    pub fn event(mut self) -> Self {
        self.querry.push_str("event, ");
        self
    }

    pub fn date(mut self) -> Self {
        self.querry.push_str("date, ");
        self
    }

    pub fn custom(mut self, custom: &str) -> Self {
        self.querry.push_str(custom);
        self
    }
}

impl Query for Displayed {
    fn to_sql(&self) -> String {
        if self.querry.is_empty() {
            return "*".to_string();
        } else {
            self.querry
                .trim_end_matches(|c| c == ' ' || c == ',')
                .to_string()
        }
    }
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
/// STILL A WIP
struct InsertQuery {
    table_name: String,
    fields: InsertFields,
    values: InsertValues,
}

impl InsertQuery {
    fn fields(mut self, fields: InsertFields) -> Self {
        self.fields = fields;
        self
    }

    fn values(mut self, values: InsertValues) -> Self {
        self.values = values;
        self
    }

    fn table_name(mut self, table_name: String) -> Self {
        self.table_name = table_name;
        self
    }
}

#[derive(Default)]
struct DeleteQuery {
    condition: Option<Condition>, // or Query in general
    table_name: String,
}

impl DeleteQuery {
    pub fn table_name(mut self, table_name: String) -> Self {
        self.table_name = table_name;
        self
    }

    pub fn condition(mut self, condition: Condition) -> Self {
        self.condition = Some(condition);
        self
    }
}

impl Query for DeleteQuery {
    fn to_sql(&self) -> String {
        let mut query = format!("DELETE FROM {}", self.table_name);
        if let Some(cond) = &self.condition {
            query.push_str(&format!(" {}", cond.to_sql()));
        };
        query
    }
}

impl Query for String {
    fn to_sql(&self) -> String {
        self.clone()
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
    #[serde(alias = "legal")]
    Web,
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
    fn search_query_test() {
        let condition = Condition::default()
            .condition(&SearchInfo::Matrix("matrix_acc".to_string()))
            .and()
            .condition(&SearchInfo::Twitter("troll".to_string()))
            .or()
            .condition(&SearchInfo::Matrix("anon".to_string()))
            .and()
            .condition(&SearchInfo::Web("example.com".to_string()));

        let query = SimpleSearchQuery::default().table_name("registration".to_string());

        assert_eq!(query.to_sql(), "SELECT * FROM registration");

        let displayed = Displayed::default()
            .wallet_id()
            .account(AccountType::Email)
            .account(AccountType::Discord);

        let query = SimpleSearchQuery::default()
            .table_name("registration".to_string())
            .selected(displayed);

        assert_eq!(
            query.to_sql(),
            "SELECT wallet_id, email, discord FROM registration"
        );

        let query = SimpleSearchQuery::default()
            .table_name("registration".to_string())
            .condition(condition);

        assert_eq!(
            query.to_sql(),
            "SELECT * FROM registration WHERE matrix='matrix_acc' AND twitter='troll' OR matrix='anon' AND web='example.com'"
        );

        let condition = Condition::default().condition(&SearchInfo::Twitter("HIO".to_string()));

        let displayed = Displayed::default()
            .wallet_id()
            .account(AccountType::Email)
            .account(AccountType::Discord);

        SimpleSearchQuery::default()
            .table_name("timeline_elem".to_string())
            .limit(Some(Limit::new(4)))
            .selected(displayed)
            .condition(condition);
    }

    #[test]
    fn delete_query_test() {
        let table_name = "registration".to_string();
        let condition = Condition::default()
            .condition(&SearchInfo::Matrix("matrix_acc".to_string()))
            .and()
            .condition(&SearchInfo::Twitter("troll".to_string()))
            .or()
            .condition(&SearchInfo::Matrix("anon".to_string()))
            .and()
            .condition(&SearchInfo::Web("example.com".to_string()));

        let delete_query = DeleteQuery::default()
            .table_name(table_name)
            .condition(condition);
        assert_eq!(
            delete_query.to_sql(),
            "DELETE FROM registration WHERE matrix='matrix_acc' AND twitter='troll' OR matrix='anon' AND web='example.com'"
            );

        let delete_query = DeleteQuery::default().table_name("registration".to_string());
        assert_eq!(delete_query.to_sql(), "DELETE FROM registration");
    }

    #[test]
    fn query_condition() {
        let condition = Condition::default()
            .condition(&SearchInfo::Matrix("matrix_acc".to_string()))
            .and()
            .condition(&SearchInfo::Twitter("troll".to_string()))
            .or()
            .condition(&SearchInfo::Matrix("anon".to_string()))
            .and()
            .condition(&SearchInfo::Web("example.com".to_string()))
            .and();

        assert_eq!(
            condition.to_sql(),
            "WHERE matrix='matrix_acc' AND twitter='troll' OR matrix='anon' AND web='example.com'"
        );

        let condition = Condition::default()
            .like_condition(&SearchInfo::Matrix("matrix_acc".to_string()))
            .and()
            .like_condition(&SearchInfo::Twitter("troll".to_string()))
            .or()
            .like_condition(&SearchInfo::Matrix("anon".to_string()))
            .and()
            .like_condition(&SearchInfo::Web("example.com".to_string()))
            .and();

        assert_eq!(
            condition.to_sql(),
            "WHERE matrix LIKE '%matrix_acc%' AND twitter LIKE '%troll%' OR matrix LIKE '%anon%' AND web LIKE '%example.com%'"
        );

        let condition = Condition::default();

        assert_eq!(condition.to_sql(), String::new());

        let condition = Condition::default()
            .network(&Network::Paseo)
            .or()
            .network(&Network::Polkadot)
            .and()
            .condition(&SearchInfo::Twitter("troll".to_string()));

        assert_eq!(
            condition.to_sql(),
            "WHERE network='Paseo' OR network='Polkadot' AND twitter='troll'"
        );
    }

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
        let search_query: SimpleSearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT wallet_id, display_name FROM registration WHERE network='Rococo' AND display LIKE '%Travis Hernandez%' AND discord='Travis Hernandez' LIMIT 2"
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

        let search_query: SimpleSearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT wallet_id, display_name FROM registration WHERE display='Travis Hernandez' LIMIT 2"
        );
        //  ------------------------------------------------------------------------------
        let outputs: Vec<DisplayedInfo> = vec![];
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let search_query: SimpleSearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT * FROM registration WHERE display='Travis Hernandez' LIMIT 2"
        );
        //  ------------------------------------------------------------------------------
        let filters: Filter = Filter::default();
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let search_query: SimpleSearchQuery = search_req.into();

        assert_eq!(search_query.to_sql(), "SELECT * FROM registration");
    }

    #[test]
    fn search_by_date() {
        let mut timeline_query = TimelineQuery::default();
        let selected = Displayed::default().wallet_id().event().date();
        let date = NaiveDate::from_ymd_opt(2015, 6, 3).unwrap();
        let time_filter = TimeFilter {
            gt: Some(date),
            lt: None,
            // eq: None,
        };
        let mut condition = Condition::default()
            .date(&time_filter)
            .and()
            .network(&Network::Paseo);

        let mut sql = timeline_query
            .selected(selected)
            .condition(condition)
            .to_sql();
        assert_eq!(sql, "SELECT wallet_id, event, date FROM timeline_elem WHERE date > '2015-06-03' AND network='paseo'");
    }

    #[test]
    fn insert_query_test() {
        // InsertQuery
    }
}
