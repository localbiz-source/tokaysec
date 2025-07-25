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
    "target_type" TEXT NOT NULL,
    "action" INT NOT NULL DEFAULT 0, -- 0 = Deny, 1 = Allow
    "resource" TEXT NOT NULL, -- Resource is instance, namespace, project, secret
    "resource_type" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokaysec.permissions (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "permission" TEXT NOT NULL,
    "scope_level" TEXT, -- What level created it : instance, namespace, project
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS tokaysec.resource_assignment (
    "resource" TEXT NOT NULL, -- can reference role:<id> or permission:<id>
    "resource_type" TEXT NOT NULL, -- IN ("role", "inst", "perm", "nmsp", "proj", "user", "sect"),
    "assigned_to" TEXT NOT NULL, -- leaving this un-"referenced". might allow it to be assigned else where
    "assigned_to_type" TEXT NOT NULL, -- IN ("role", "inst", "perm", "nmsp", "proj", "user", "sect"),
    "assigned_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    "assigned_by" TEXT NOT NULL REFERENCES tokaysec.people("id")
);


CREATE TABLE IF NOT EXISTS tokaysec.namespaces (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    "created_by" TEXT NOT NULL REFERENCES tokaysec.people("id") ON DELETE CASCADE,
    "last_updated" TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tokaysec.projects (
    "id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "name" TEXT NOT NULL,
    "kek_id" TEXT UNIQUE NOT NULL,
    "namespace" TEXT NOT NULL REFERENCES tokaysec.namespaces("id"),
    "added_when" TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);