-- V2: Add tenant isolation, MFA recovery codes, correlation fields, coverage registry
-- Add organization_id to findings and scans for tenant isolation
ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_id UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_json TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(50);

-- MFA recovery codes
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_codes TEXT;

-- Indexes for tenant queries
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
