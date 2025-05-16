// @generated automatically by Diesel CLI.

diesel::table! {
    account (id) {
        id -> Int4,
        address_id -> Int4,
        name -> Varchar,
        varified -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    address (id) {
        id -> Int4,
        network -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        public_key -> Bytea,
    }
}

diesel::joinable!(account -> address (address_id));

diesel::allow_tables_to_appear_in_same_query!(
    account,
    address,
);
