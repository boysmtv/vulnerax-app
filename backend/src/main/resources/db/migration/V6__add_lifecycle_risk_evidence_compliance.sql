-- V6: Full lifecycle, risk separation, evidence, compliance, validation
-- P0.4: Security Risk vs Coverage Risk
ALTER TABLE findings ADD COLUMN security_risk DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN coverage_risk DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN security_risk_level VARCHAR(32);
ALTER TABLE findings ADD COLUMN coverage_risk_level VARCHAR(32);
ALTER TABLE findings ADD COLUMN risk_breakdown TEXT;

-- P0.1: Evidence Schema integration
ALTER TABLE findings ADD COLUMN evidence_strength VARCHAR(32);
ALTER TABLE findings ADD COLUMN detection_confidence DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN classification_confidence DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN vulnerability_confidence DOUBLE PRECISION;

-- P0.2: Classification Engine
ALTER TABLE findings ADD COLUMN finding_subtype VARCHAR(64);
ALTER TABLE findings ADD COLUMN coverage_percentage DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN scan_subtype VARCHAR(64);

-- P2.3: OWASP ASVS/WSTG mapping
ALTER TABLE findings ADD COLUMN asvs_req VARCHAR(128);
ALTER TABLE findings ADD COLUMN wstg_test VARCHAR(128);

-- P2.4: Next best action
ALTER TABLE findings ADD COLUMN next_best_action VARCHAR(256);
ALTER TABLE findings ADD COLUMN next_best_action_priority VARCHAR(16);

-- P2.5: Validation gate
ALTER TABLE findings ADD COLUMN validated BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN ready_for_publish BOOLEAN DEFAULT FALSE;

-- Indexes
CREATE INDEX idx_findings_security_risk ON findings(security_risk);
CREATE INDEX idx_findings_coverage_risk ON findings(coverage_risk);
CREATE INDEX idx_findings_validated ON findings(validated);
CREATE INDEX idx_findings_ready_for_publish ON findings(ready_for_publish);
CREATE INDEX idx_findings_evidence_strength ON findings(evidence_strength);
