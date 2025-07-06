-- Add migration script here

CREATE SCHEMA IF NOT EXISTS tokaysec;


CREATE TABLE IF NOT EXISTS tokaysec.people (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "flags" BIGINT NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMPTZ NOT NULL,
    "created_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.credentials (
    "id" TEXT UNIQUE NOT NULL PRIMARY KEY,
    "created_by" TEXT NOT NULL REFERENCES tokaysec.people("id"),
    "public_key" BYTEA NOT NULL UNIQUE,
    "count" BIGINT NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMPTZ NOT NULL,
    "created_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.roles (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "scope_level" TEXT, -- What level created it : instance, namespace, project
    "defined_by" TEXT NOT NULL -- proj:, nmsp:, inst:
);

CREATE TABLE IF NOT EXISTS tokaysec.policy_rule_target (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "target" TEXT NOT NULL, -- person:<id>, role:<id>, perm:<permission>
    "action" INT NOT NULL DEFAULT 0, -- 0 = Deny, 1 = Allow
    "resource" TEXT NOT NULL -- Resource is instance, namespace, project, secret
);

CREATE TABLE IF NOT EXISTS tokaysec.permissions (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "permission" TEXT NOT NULL,
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.resource_assignment (
    "resource" TEXT NOT NULL, -- can reference role:<id> or permission:<id>
    "assigned_to" TEXT NOT NULL, -- leaving this un-"referenced". might allow it to be assigned else where
    "assigned_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    "assigned_by" TEXT NOT NULL REFERENCES tokaysec.people("id")
);

CREATE TABLE IF NOT EXISTS tokaysec.projects (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.namespaces (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
    -- "created_by" TEXT NOT NULL REFERENCES tokaysec.people("id") ON DELETE CASCADE,
    -- "created_when" TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    -- "last_updated" TIMESTAMP WITHOUT TIME ZONE NOT NULL,
);