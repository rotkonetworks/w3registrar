create table if not exists blocks (
    number integer not null primary key,
    hash text not null unique,
    event_count integer not null
);
--
create table if not exists events (
    block_number integer,
    number integer,
    kind text,
    account_id text,
    primary key (block_number, number)
);
