-- Add migration script here

CREATE TABLE IF NOT EXISTS tokaysec.wrapped_deks (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "wrapped" BYTEA NOT NULL,
    "nonce" BYTEA NOT NULL,
    "tag" BYTEA NOT NULL,
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    "added_by" TEXT NOT NULL REFERENCES tokaysec.people("id")
);

CREATE TABLE IF NOT EXISTS tokaysec.kv_store (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "key" TEXT NOT NULL UNIQUE,
    "value" BYTEA NOT NULL,
    "gcm_tag" BYTEA NOT NULL,
    "kmac_tag" BYTEA NOT NULL,
    "nonce" BYTEA NOT NULL,
    "dek_used" TEXT NOT NULL REFERENCES tokaysec.wrapped_deks("id"),
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    "added_by" TEXT NOT NULL REFERENCES tokaysec.people("id"),
    "last_updated" TIMESTAMPTZ NOT NULL
);