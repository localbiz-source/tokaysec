-- Add migration script here

CREATE TABLE IF NOT EXISTS kek_store (
    id TEXT PRIMARY KEY,
    wrapped_kek BLOB NOT NULL
);