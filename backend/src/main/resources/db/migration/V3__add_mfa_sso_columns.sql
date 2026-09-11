-- V3: add MFA and SSO columns missing from V1
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(255);
