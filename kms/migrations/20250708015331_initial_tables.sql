-- Add migration script here

CREATE TABLE IF NOT EXISTS kek_store (
    id TEXT PRIMARY KEY,
    wrapped_kek BLOB NOT NULL,
    persistent_handle INTEGER NOT NULL,
    wrapped_priv_key BLOB NOT NULL, 
    wrapped_pub_key BLOB NOT NULL
    -- nonce BLOB NOT NULL,
    -- tag BLOB NOT NULL
);