use std::str::FromStr;
// TODO: add stuff that registers what a user do, like someone requested this thing or that thing
// etc
// TODO: add table name for the queries?

use subxt::utils::AccountId32;
use tokio_postgres::{Client, NoTls};
use tracing::info;

use crate::{
    api::{identity_data_tostring, Account, AccountType},
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
            wallet_id       VARCHAR (48) PRIMARY KEY,
            discord         TEXT,
            twitter         TEXT,
            matrix          TEXT,
            email           TEXT,
            display_name    TEXT,
            github          TEXT,
            legal           TEXT,
            web             TEXT,
            pgp_fingerprint VARCHAR (20)
        )";
        info!("QUERRY: {:?}", create_reg_record);
        self.client.simple_query(create_reg_record).await?;

        info!("Table `registration` created");
        Ok(())
    }

    pub async fn write(&mut self, record: &Record) -> anyhow::Result<()> {
        info!(who = ?record.wallet_id(), "Writing record");
        let insert_reg_record =
            "INSERT INTO registration (wallet_id, discord, twitter, matrix, email, display_name, github, legal, web, pgp_fingerprint)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ";
        info!("QUERRY: {:?}", insert_reg_record);

        self.client
            .execute(
                insert_reg_record,
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

    pub async fn search<Q>(&mut self, search_querry: Q) -> anyhow::Result<Vec<Record>>
    where
        Q: Query,
    {
        Ok(self
            .client
            .simple_query(&search_querry.to_sql())
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
        conn_cfg
            .user(&cfg.user)
            .host(&cfg.host)
            .port(cfg.port)
            .dbname(&cfg.dbname);
        if let Some(pwd) = &cfg.password {
            conn_cfg.password(pwd);
        };
        let (client, connection) = conn_cfg.connect(NoTls).await?;

        let _join_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
        info!("New postgress connection established!");

        Ok(Self { client })
    }
}

#[derive(Debug)]
pub struct Record {
    wallet_id: AccountId32,
    pub discord: Option<String>,
    pub twitter: Option<String>,
    pub matrix: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub github: Option<String>,
    pub legal: Option<String>,
    pub web: Option<String>,
    pub pgp_fingerprint: Option<String>,
}

impl Record {
    pub fn from_registration(
        acc: &AccountId32,
        registration: &Registration<u128, IdentityInfo>,
    ) -> Self {
        let pgp_fingerprint = match registration.info.pgp_fingerprint {
            Some(bytes) => Some(hex::encode(bytes)),
            None => None,
        };
        Self {
            wallet_id: acc.to_owned(),
            discord: identity_data_tostring(&registration.info.discord),
            twitter: identity_data_tostring(&registration.info.twitter),
            matrix: identity_data_tostring(&registration.info.matrix),
            email: identity_data_tostring(&registration.info.email),
            display_name: identity_data_tostring(&registration.info.display),
            github: identity_data_tostring(&registration.info.github),
            legal: identity_data_tostring(&registration.info.legal),
            web: identity_data_tostring(&registration.info.web),
            pgp_fingerprint,
        }
    }

    // TODO: return None if judgement is not set correctly
    pub async fn from_judgement(jud: &JudgementGiven) -> anyhow::Result<Option<Self>> {
        let cfg = GLOBAL_CONFIG
            .get()
            .expect("GLOBAL_CONFIG is not initialized");

        let reg_config = match cfg.registrar.registrar_config(jud.registrar_index) {
            Some(v) => v,
            None => return Ok(None),
        };

        let client = NodeClient::from_url(&reg_config.endpoint).await?;
        let registration = node::get_registration(&client, &jud.target).await?;
        Ok(Some(Self::from_registration(&jud.target, &registration)))
    }

    pub fn wallet_id(&self) -> String {
        self.wallet_id.to_owned().to_string()
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

    pub fn from(row: &tokio_postgres::SimpleQueryMessage) -> Self {
        match row {
            tokio_postgres::SimpleQueryMessage::Row(simple_query_row) => Self {
                wallet_id: AccountId32::from_str(simple_query_row.get("wallet_id").unwrap())
                    .unwrap(),
                display_name: simple_query_row
                    .get("display")
                    .and_then(|v| Some(v.to_string())),
                discord: simple_query_row
                    .get("discord")
                    .and_then(|v| Some(v.to_string())),
                twitter: simple_query_row
                    .get("twitter")
                    .and_then(|v| Some(v.to_string())),
                matrix: simple_query_row
                    .get("matrix")
                    .and_then(|v| Some(v.to_string())),
                github: simple_query_row
                    .get("github")
                    .and_then(|v| Some(v.to_string())),
                email: simple_query_row
                    .get("email")
                    .and_then(|v| Some(v.to_string())),
                web: simple_query_row
                    .get("web")
                    .and_then(|v| Some(v.to_string())),
                legal: simple_query_row
                    .get("legal")
                    .and_then(|v| Some(v.to_string())),
                pgp_fingerprint: simple_query_row
                    .get("pgp_fingerprint")
                    .and_then(|v| Some(v.to_string())),
            },
            tokio_postgres::SimpleQueryMessage::CommandComplete(_) => unimplemented!(),
            tokio_postgres::SimpleQueryMessage::RowDescription(arc) => unimplemented!(),
            _ => todo!(),
        }
    }
}

pub trait Query {
    fn to_sql(&self) -> String;
}

#[derive(Default)]
struct SearchQuery {
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
        match &self.condition {
            Some(cond) => querry.push_str(&format!(" WHERE {}", cond.to_sql())),
            None => {}
        }
        querry
    }
}

#[derive(Default)]
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

    pub fn account(mut self, account: &Account) -> Self {
        let query = match account {
            Account::Twitter(account) => format!("twitter='{}' ", account),
            Account::Discord(account) => format!("discord='{}' ", account),
            Account::Matrix(account) => format!("matrix='{}' ", account),
            Account::Display(account) => format!("display='{}' ", account),
            Account::Legal(account) => format!("legal='{}' ", account),
            Account::Web(account) => format!("web='{}' ", account),
            Account::Email(account) => format!("email='{}' ", account),
            Account::Github(account) => format!("github='{}' ", account),
            Account::PGPFingerprint(bytes) => {
                format!(" pgp_fingerprint='{}' ", hex::encode(bytes))
            }
        };
        self.querry.push_str(&query);
        self
    }

    pub fn wallet_id(mut self, wallet_id: &AccountId32) -> Self {
        self.querry.push_str(&wallet_id.to_string());
        self
    }
}

impl Query for Condition {
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
            AccountType::Discord => format!("discord,  "),
            AccountType::Matrix => format!("matrix, "),
            AccountType::Display => format!("display, "),
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
            query.push_str(&format!(" WHERE {}", cond.to_sql()));
        };
        query
    }
}

impl Query for String {
    fn to_sql(&self) -> String {
        self.clone()
    }
}

mod test {
    use super::*;
    #[test]
    fn search_query_test() {
        let condition = Condition::default()
            .account(&Account::Matrix("matrix_acc".to_string()))
            .and()
            .account(&Account::Twitter("troll".to_string()))
            .or()
            .account(&Account::Matrix("anon".to_string()))
            .and()
            .account(&&Account::Web("example.com".to_string()));

        let displayed = Displayed::default()
            .wallet_id()
            .account(AccountType::Email)
            .account(AccountType::Discord);

        let query = SearchQuery::default().table_name("registration".to_string());
        assert_eq!(query.to_sql(), "SELECT * FROM registration");

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
            .account(&Account::Matrix("matrix_acc".to_string()))
            .and()
            .account(&Account::Twitter("troll".to_string()))
            .or()
            .account(&Account::Matrix("anon".to_string()))
            .and()
            .account(&&Account::Web("example.com".to_string()));

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
}
