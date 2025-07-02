-- Add migration script here

CREATE SCHEMA IF NOT EXISTS tokaysec;


CREATE TABLE IF NOT EXISTS tokaysec.people (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "flags" BIGINT NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    "created_when" TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.credentials (
    "id" TEXT UNIQUE NOT NULL PRIMARY KEY,
    "created_by" TEXT NOT NULL REFERENCES tokaysec.people("id") ON DELETE CASCADE,
    "public_key" BYTEA NOT NULL UNIQUE,
    "count" INT NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMP WITHOUT TIME ZONE NOT NULL
    "created_when" TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
);

CREATE TABLE IF NOT EXISTS tokaysec.roles {
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "permissions" TEXT[],
    "scope_level" TEXT,
};

CREATE TABLE IF NOT EXISTS tokaysec.policy_target_rule (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "target" TEXT NOT NULL -- person_<id>, role_<id>,
    "action" INT NOT NULL DEFAULT 0, -- 0 = Deny, 1 = Allow
    "resource" TEXT NOT NULL -- Resource is instance, namespace, project, secret
);

CREATE TABLE IF NOT EXISTS tokaysec.projects {
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
};

CREATE TABLE IF NOT EXISTS tokaysec.namespaces {
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    -- "created_by" TEXT NOT NULL REFERENCES tokaysec.people("id") ON DELETE CASCADE,
    -- "created_when" TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    -- "last_updated" TIMESTAMP WITHOUT TIME ZONE NOT NULL,
};