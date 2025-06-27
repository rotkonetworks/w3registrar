#![allow(unused)]
// TODO: add table name for the queries?

use anyhow::anyhow;
use openssl::ssl::{SslConnector, SslMethod};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, time::Duration};
use subxt::utils::AccountId32;
use tokio_postgres::{Client, NoTls};
use tracing::{error, info};

use crate::{
    api::{identity_data_tostring, AccountType, Filter, IncomingSearchRequest, Network},
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
    client: Client,
}

impl PostgresConnection {
    pub async fn init_tables(&mut self) -> anyhow::Result<()> {
        info!("Creating `registration` table");
        // TODO: parametarize table name?
        let create_reg_record = "CREATE TABLE IF NOT EXISTS registration (
            wallet_id       VARCHAR (48),
            network         TEXT,
            discord         TEXT,
            twitter         TEXT,
            matrix          TEXT,
            email           TEXT,
            display_name    TEXT,
            github          TEXT,
            legal           TEXT,
            web             TEXT,
            pgp_fingerprint VARCHAR (20),
            PRIMARY KEY (wallet_id, network)
        )";
        info!("QUERRY");
        info!("{create_reg_record}");
        self.client.simple_query(create_reg_record).await?;

        info!("Table `registration` created");
        Ok(())
    }

    pub async fn write(&mut self, record: &Record) -> anyhow::Result<()> {
        info!(who = ?record.wallet_id(), "Writing record");
        let insert_reg_record =
            "INSERT INTO registration(wallet_id, network, discord, twitter, matrix, email, display_name, github, legal, web, pgp_fingerprint)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        info!(query=?insert_reg_record,"QUERRY");

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

    pub async fn search<Q>(&mut self, search_querry: Q) -> anyhow::Result<Vec<Record>>
    where
        Q: Query,
    {
        Ok(self
            .client
            .query(&search_querry.to_sql(), &[])
            .await?
            .iter()
            .map(Record::from)
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

        Ok(Self { client })
    }

    pub async fn default() -> anyhow::Result<Self> {
        let cfg = GLOBAL_CONFIG.get().unwrap();
        let pog_config = cfg.postgres.clone();
        PostgresConnection::new(&pog_config).await
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_id: Option<String>,

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
    pub network: Option<Network>,
}

impl Record {
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
            network,
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

impl From<&tokio_postgres::Row> for Record {
    fn from(value: &tokio_postgres::Row) -> Self {
        let mut record = Record::default();
        let displayed_info: Vec<DisplayedInfo> = value
            .columns()
            .iter()
            .map(|v| DisplayedInfo::from_str(v.name()))
            .filter_map(|v| v.ok())
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
            }
        }

        return record;
    }
}

pub trait Query {
    fn to_sql(&self) -> String;
}

#[derive(Default)]
pub struct SearchQuery {
    displayed: Displayed,
    condition: Option<Condition>,
    table_name: String,
}

impl SearchQuery {
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

impl Query for SearchQuery {
    fn to_sql(&self) -> String {
        let mut querry = format!(
            "SELECT {} FROM {}",
            self.displayed.to_sql(),
            self.table_name
        );

        let cond = match &self.condition {
            Some(cond) => &format!(" {}", cond.to_sql()),
            None => "",
        };
        querry.push_str(cond.trim_end());

        querry
    }
}

#[derive(Default, Debug)]
pub struct Condition {
    querry: String,
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
                format!(" pgp_fingerprint LIKE '%{}%' ", hex::encode(bytes))
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
        self
    }

    pub fn wallet_id(mut self, wallet_id: &AccountId32) -> Self {
        self.querry.push_str(&wallet_id.to_string());
        self
    }
}

impl FromStr for Condition {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            querry: s.to_owned(),
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

impl Displayed {
    pub fn wallet_id(mut self) -> Self {
        self.querry.push_str(&format!("wallet_id, "));
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

mod test {
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

        let query = SearchQuery::default().table_name("registration".to_string());
        assert_eq!(query.to_sql(), "SELECT * FROM registration");

        let displayed = Displayed::default()
            .wallet_id()
            .account(AccountType::Email)
            .account(AccountType::Discord);

        let query = SearchQuery::default()
            .table_name("registration".to_string())
            .selected(displayed);

        assert_eq!(
            query.to_sql(),
            "SELECT wallet_id, email, discord FROM registration"
        );

        let query = SearchQuery::default()
            .table_name("registration".to_string())
            .condition(condition);
        assert_eq!(
            query.to_sql(),
            "SELECT * FROM registration WHERE matrix='matrix_acc' AND twitter='troll' OR matrix='anon' AND web='example.com'"
        );
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
            "WHERE network='paseo' OR network='polkadot' AND twitter='troll'"
        );
    }

    #[test]
    fn from_search_request() {
        let network: Option<Network> = Some(Network::Rococo);
        let outputs: Vec<DisplayedInfo> = vec![DisplayedInfo::WalletID, DisplayedInfo::Display];
        let filters: Vec<Filter> = vec![Filter::new(
            SearchInfo::Display("Travis Hernandez".to_string()),
            true,
        )];

        let search_req = IncomingSearchRequest::new(network, outputs.clone(), filters.clone());
        let search_query: SearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT wallet_id, display_name FROM registration WHERE network='rococo' AND display='Travis Hernandez'"
        );
        //  ------------------------------------------------------------------------------
        let network: Option<Network> = None;

        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());
        let search_query: SearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT wallet_id, display_name FROM registration WHERE display='Travis Hernandez'"
        );
        //  ------------------------------------------------------------------------------
        let outputs: Vec<DisplayedInfo> = vec![];
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let search_query: SearchQuery = search_req.into();

        assert_eq!(
            search_query.to_sql(),
            "SELECT * FROM registration WHERE display='Travis Hernandez'"
        );
        //  ------------------------------------------------------------------------------
        let filters: Vec<Filter> = vec![];
        let search_req =
            IncomingSearchRequest::new(network.clone(), outputs.clone(), filters.clone());

        let search_query: SearchQuery = search_req.into();

        assert_eq!(search_query.to_sql(), "SELECT * FROM registration");
    }
}
