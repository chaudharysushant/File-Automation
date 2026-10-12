CREATE TABLE IF NOT EXISTS zph_ftp.dashboard_account (
    account_id SMALLINT PRIMARY KEY CHECK (account_id = 1),
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    reset_token_hash TEXT,
    reset_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE zph_ftp.dashboard_account
    ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;

ALTER TABLE zph_ftp.dashboard_account
    ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMPTZ;