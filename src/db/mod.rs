use diesel::{Connection, PgConnection};
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
