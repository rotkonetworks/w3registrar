use diesel::{Connection, PgConnection};
use mail_parser::core::address;
use matrix_sdk::Account;
use subxt::utils::AccountId32;
use tracing::info;

use crate::config::GLOBAL_CONFIG;

pub mod schema;
pub mod models;

pub fn get_connection() -> PgConnection {
    let config = GLOBAL_CONFIG.get().expect("GLOBAL_CONFIG must be set up!");
    let database_url = config.postgres.database_url.clone();

    let pg_connection = PgConnection::establish(&database_url).expect(&format!(
        "Error connecting to {}",
        database_url
    ));
    info!("Connected to PostgreSQL database at {}", database_url);
    pg_connection
}

// Insert or update accounts for a given address_id, and delete those not present in the list.
pub fn upsert_accounts(
    pg_connection: &PgConnection,
    address_id: i32,
    accounts: &std::collections::HashMap<crate::api::Account, bool>,
) -> Result<(), diesel::result::Error> {
    use crate::db::schema::account;
    use diesel::{insert_into, delete, prelude::*, dsl::any};
    use chrono::Utc;

    let now = Utc::now().naive_utc();

    for (account, is_done) in accounts {
        // Use a simple select query to avoid any potential type mismatches
        let existing_account = account::table
            .filter(account::address_id.eq(address_id))
            .filter(account::type_.eq(account.account_type().to_string()))
            .select((account::id, account::type_))
            .first::<(i32, String)>(pg_connection)
            .optional()?;

        if let Some(_) = existing_account {
            // Account exists, no need to create a new one
            // If you need to update it, you would do so here
            // TODO Update updated_at
        } else {
            // Insert a new account
            insert_into(account::table)
                .values((
                    account::address_id.eq(address_id),
                    account::type_.eq(account.account_type().to_string()),
                    account::name.eq(account.inner()),
                    account::varified.eq(is_done),
                    account::created_at.eq(now),
                    account::updated_at.eq(now),
                ))
                .execute(pg_connection)
                .expect("Failed to insert new account");
        }
    }
    // Delete every account that is not in the list
    delete(account::table)
        .filter(account::address_id.eq(address_id))
        .filter(
            account::type_.ne(any(
                &accounts
                    .iter()
                    .map(|(acc, _)| acc.account_type().to_string())
                    .collect::<Vec<_>>(),
            )),
        )
        .execute(pg_connection)
        .expect("Failed to delete accounts");

    Ok(())
}

pub fn upsert_address_and_accounts(
    network: &str,
    address: &AccountId32,
    accounts: &std::collections::HashMap<crate::api::Account, bool>,
) -> Result<(), diesel::result::Error> {
    let public_key_bytes: &[u8] = <AccountId32 as AsRef<[u8]>>::as_ref(address);

    use crate::db::schema::{address, account};
    use crate::db::models::{NewPgAddress, PgAddress};
    use diesel::{insert_into, delete, prelude::*, dsl::any};
    use chrono::Utc;

    let pg_connection = get_connection();

    // Find or insert address
    let pg_address = address::table
        .filter(address::network.eq(network))
        .filter(address::public_key.eq(public_key_bytes))
        .first::<PgAddress>(&pg_connection)
        .optional()?
        .unwrap_or_else(|| {
            insert_into(address::table)
                .values(NewPgAddress {
                    network,
                    public_key: public_key_bytes,
                })
                .get_result::<PgAddress>(&pg_connection)
                .expect("Failed to insert new address")
        });

    upsert_accounts(&pg_connection, pg_address.id, accounts)
}
