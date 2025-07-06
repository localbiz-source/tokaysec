-- Add migration script here

CREATE TABLE IF NOT EXISTS tokaysec.config (
    "key" TEXT UNIQUE NOT NULL,
    "value" JSONB NOT NULL
);

INSERT INTO tokaysec.config ("key","value") VALUES('intially_initialized', 'false'::jsonb);