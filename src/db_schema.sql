create table if not exists blocks (
    number integer primary key not null,
    hash text not null unique
);

create table if not exists events (
    block_number integer,
    number integer,
    kind text,
    account_id text,
    primary key (block_number, number)
);
