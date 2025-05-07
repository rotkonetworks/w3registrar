use diesel::{Connection, PgConnection};

use crate::config::GLOBAL_CONFIG;

pub mod schema;

pub fn get_connection() -> PgConnection {
    let config = GLOBAL_CONFIG.get().expect("GLOBAL_CONFIG must be set up!");
    let database_url = config.postgres.database_url.clone();

    PgConnection::establish(&database_url).unwrap()
}
