CREATE TABLE IF NOT EXISTS zph_ftp.dashboard_account (
    account_id SMALLINT PRIMARY KEY CHECK (account_id = 1),
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);