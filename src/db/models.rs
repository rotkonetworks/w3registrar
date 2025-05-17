use chrono::{DateTime, Utc};
use serde::{Serialize};
use diesel::prelude::*;
use crate::db::schema::address;
use crate::db::schema::account;
use chrono::NaiveDateTime;

#[derive(Queryable, Identifiable, Debug, Clone, Serialize)]
#[table_name = "address"]
pub struct PgAddress {
    pub id: i32,
    pub network: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub public_key: Vec<u8>,
}

#[derive(Insertable, Debug, Clone, Serialize)]
#[table_name = "address"]
pub struct NewPgAddress<'a> {
    pub network: &'a str,
    pub public_key: &'a [u8],
}

// Updatable struct for address
#[derive(AsChangeset, Debug, Clone)]
#[table_name = "address"]
pub struct UpdateAddress<'a> {
    pub network: Option<&'a str>,
    pub public_key: Option<&'a [u8]>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Queryable, Identifiable, Debug, Clone, Serialize)]
#[table_name = "account"]
pub struct Account {
    pub id: i32,
    pub address_id: i32,
    pub type_: String,
    pub name: String,
    pub varified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable, Debug, Clone, Serialize)]
#[table_name = "account"]
pub struct NewAccount<'a> {
    pub address_id: i32,
    pub type_: &'a str,
    pub name: &'a str,
    pub varified: bool,
}

// Updatable struct for account
#[derive(AsChangeset, Debug, Clone)]
#[table_name = "account"]
pub struct UpdateAccount<'a> {
    pub type_: Option<&'a str>,
    pub name: Option<&'a str>,
    pub varified: Option<bool>,
    pub updated_at: Option<NaiveDateTime>,
}
