-- Automatic transfer mode settings.
--
-- Stores the dashboard's automatic-mode flag and the last scheduled run time so
-- the hourly scheduler resumes correctly after an application/container restart.
-- The application also creates this table on startup (CREATE TABLE IF NOT
-- EXISTS), so running this file manually is optional.
--
-- This file is idempotent.

CREATE TABLE IF NOT EXISTS zph_ftp.file_automation_setting (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed the automatic-mode flag as disabled on first deploy.
INSERT INTO zph_ftp.file_automation_setting (setting_key, setting_value)
VALUES ('auto_mode_enabled', 'false')
ON CONFLICT (setting_key) DO NOTHING;
