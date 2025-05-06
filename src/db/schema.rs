// @generated automatically by Diesel CLI.

diesel::table! {
    account (id) {
        id -> Int4,
        address -> Varchar,
        network -> Varchar,
    }
}

diesel::table! {
    challenge (id) {
        id -> Int4,
        account_id -> Int4,
        secret -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::joinable!(challenge -> account (account_id));

diesel::allow_tables_to_appear_in_same_query!(
    account,
    challenge,
);
