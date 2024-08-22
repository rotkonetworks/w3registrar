create table if not exists blocks (
    number integer primary key not null,
    hash text unique not null,
    event_count integer not null
)
