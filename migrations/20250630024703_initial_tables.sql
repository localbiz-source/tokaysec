-- Add migration script here

CREATE SCHEMA IF NOT EXISTS tokaysec;

CREATE TABLE IF NOT EXISTS tokaysec.kv_store (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "key" TEXT NOT NULL,
    "secret" JSONB NOT NULL,
    "created_when" TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);