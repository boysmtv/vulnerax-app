-- V3: Performance indexes, SLA tracking, data classification, evidence enhancements
-- Performance indexes for hot queries
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_kev ON findings(kev);
CREATE INDEX IF NOT EXISTS idx_findings_severity_created ON findings(severity, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_status_sla ON findings(status, sla_due_at);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(type);
CREATE INDEX IF NOT EXISTS idx_evidence_validated ON evidence(validated);
CREATE INDEX IF NOT EXISTS idx_evidence_sha ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scanner_type);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);

-- SLA breach tracking
ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS sla_due_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS sla_status VARCHAR(20) DEFAULT 'WITHIN_SLA';

-- Data classification support
ALTER TABLE findings ADD COLUMN IF NOT EXISTS data_classification VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS compensating_control TEXT;

-- Evidence enhancements
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS request_method VARCHAR(10);
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS request_url TEXT;
ALTER TABLE evidence ADD COLUMN IF EXISTS request_body TEXT;
ALTER TABLE evidence ADD COLUMN IF EXISTS response_headers TEXT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS response_status_code INT DEFAULT 0;
ALTER TABLE evidence ADD COLUMN IF EXISTS response_body TEXT;
ALTER TABLE evidence ADD COLUMN IF EXISTS payload TEXT;
ALTER TABLE evidence ADD COLUMN IF EXISTS response_time_ms BIGINT;

-- SLA breach auto-update trigger
CREATE OR REPLACE FUNCTION update_sla_status() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'OPEN' AND NEW.sla_due_at < NOW() AND NEW.sla_status = 'WITHIN_SLA' THEN
        NEW.sla_status := 'BREACHED';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sla_status ON findings;
CREATE TRIGGER trg_sla_status BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_sla_status();
