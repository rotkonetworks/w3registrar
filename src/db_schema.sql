create table if not exists state (
    id integer not null primary key,
    last_block_hash text not null
);

create table if not exists events (
    block_number integer,
    number integer,
    kind text,
    account_id text,
    primary key (block_number, number)
);