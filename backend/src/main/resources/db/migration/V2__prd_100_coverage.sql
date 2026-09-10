-- V2: 100% PRD coverage - remaining domains

-- Threat Modeling (#33)
CREATE TABLE threat_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
    components_json TEXT NOT NULL DEFAULT '[]',
    dataflows_json TEXT NOT NULL DEFAULT '[]',
    trust_boundaries_json TEXT NOT NULL DEFAULT '[]',
    threats_json TEXT NOT NULL DEFAULT '[]',
    controls_json TEXT NOT NULL DEFAULT '[]',
    diagram_json TEXT
);

-- Pentest Engagement (#59-60)
CREATE TABLE pentest_engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    client_name VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    rules_of_engagement TEXT,
    test_window_start TIMESTAMPTZ,
    test_window_end TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'PLANNING',
    testers_json TEXT NOT NULL DEFAULT '[]',
    assets_json TEXT NOT NULL DEFAULT '[]',
    methodology VARCHAR(100) NOT NULL DEFAULT 'OWASP WSTG',
    environment VARCHAR(50) NOT NULL DEFAULT 'STAGING'
);

-- Compliance Framework (#129-130)
CREATE TABLE compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL DEFAULT 'STANDARD',
    controls_json TEXT NOT NULL DEFAULT '[]',
    mapping_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'IN_PROGRESS',
    results_json TEXT NOT NULL DEFAULT '[]',
    score DOUBLE PRECISION NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    not_applicable INTEGER NOT NULL DEFAULT 0,
    not_tested INTEGER NOT NULL DEFAULT 0
);

-- Policies & Exceptions (#127-128)
CREATE TABLE security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_json TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'HIGH',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    type VARCHAR(50) NOT NULL DEFAULT 'GATE'
);
CREATE TABLE policy_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    owner VARCHAR(255) NOT NULL,
    approver VARCHAR(255) NOT NULL,
    expiration TIMESTAMPTZ NOT NULL,
    compensating_control TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
);

-- Retest (#46)
CREATE TABLE retests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'FINDING',
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    requested_by VARCHAR(255),
    result VARCHAR(20),
    evidence_json TEXT,
    before_json TEXT,
    after_json TEXT
);

-- Cloud Resources (#24)
CREATE TABLE cloud_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,
    account_id VARCHAR(100) NOT NULL,
    region VARCHAR(50) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    name VARCHAR(255),
    configuration_json TEXT,
    risk_json TEXT,
    compliance_json TEXT,
    public_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);
CREATE INDEX idx_cloud_project ON cloud_resources(project_id);

-- K8s (#22)
CREATE TABLE k8s_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cluster_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL DEFAULT 'default',
    kind VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    configuration_json TEXT,
    risk_json TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- IaC (#23)
CREATE TABLE iac_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repository VARCHAR(500),
    file_path VARCHAR(500) NOT NULL,
    tool VARCHAR(50) NOT NULL DEFAULT 'CHECKOV',
    findings_json TEXT NOT NULL DEFAULT '[]',
    passed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'COMPLETED'
);

-- Network (#26)
CREATE TABLE network_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(50),
    port INTEGER NOT NULL,
    service VARCHAR(100),
    version VARCHAR(100),
    protocol VARCHAR(20) NOT NULL DEFAULT 'TCP',
    tls_json TEXT,
    cert_json TEXT,
    vuln_json TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN'
);
CREATE INDEX idx_network_host ON network_assets(host);

-- Database Security (#27)
CREATE TABLE database_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    engine VARCHAR(50) NOT NULL,
    version VARCHAR(100),
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    exposure_json TEXT,
    encryption_json TEXT,
    auth_json TEXT,
    audit_json TEXT,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- CI/CD Security (#28)
CREATE TABLE cicd_pipelines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    repository VARCHAR(500) NOT NULL,
    pipeline_name VARCHAR(255) NOT NULL,
    configuration_json TEXT,
    findings_json TEXT NOT NULL DEFAULT '[]',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- IAM (#25)
CREATE TABLE iam_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL DEFAULT 'AWS',
    principal_type VARCHAR(50) NOT NULL,
    principal_name VARCHAR(255) NOT NULL,
    policies_json TEXT NOT NULL DEFAULT '[]',
    permissions_json TEXT NOT NULL DEFAULT '[]',
    risk_json TEXT NOT NULL DEFAULT '{}',
    is_excessive BOOLEAN NOT NULL DEFAULT FALSE,
    is_dormant BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- Container detailed (#21)
CREATE TABLE container_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    image_name VARCHAR(500) NOT NULL,
    tag VARCHAR(100) NOT NULL DEFAULT 'latest',
    digest VARCHAR(100),
    base_image VARCHAR(255),
    dockerfile TEXT,
    packages_json TEXT NOT NULL DEFAULT '[]',
    cve_json TEXT NOT NULL DEFAULT '[]',
    misconfig_json TEXT NOT NULL DEFAULT '[]',
    secret_json TEXT NOT NULL DEFAULT '[]',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- AI/LLM (#30)
CREATE TABLE ai_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    model VARCHAR(255),
    provider VARCHAR(100),
    endpoints_json TEXT NOT NULL DEFAULT '[]',
    ragn_json TEXT,
    findings_json TEXT NOT NULL DEFAULT '[]',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- Browser Extension (#31)
CREATE TABLE browser_extensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    manifest_json TEXT NOT NULL,
    permissions_json TEXT NOT NULL DEFAULT '[]',
    findings_json TEXT NOT NULL DEFAULT '[]',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- Firmware/IoT (#32)
CREATE TABLE firmware_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    file_name VARCHAR(500) NOT NULL,
    file_size BIGINT,
    sha256 VARCHAR(100),
    filesystem_json TEXT,
    binaries_json TEXT NOT NULL DEFAULT '[]',
    cve_json TEXT NOT NULL DEFAULT '[]',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- Integrations (#81)
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    configuration_json TEXT NOT NULL DEFAULT '{}',
    credentials_encrypted TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    last_sync TIMESTAMPTZ,
    last_error TEXT
);
CREATE INDEX idx_integrations_org ON integrations(organization_id);

-- Notifications (#92)
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    channel VARCHAR(50) NOT NULL,
    recipient VARCHAR(500) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    sent_at TIMESTAMPTZ,
    error TEXT
);

-- Coverage tracking (#119-120)
CREATE TABLE security_coverages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    domain VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NOT_TESTED',
    last_scan TIMESTAMPTZ,
    coverage_percent INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(project_id, domain)
);

-- Campaign (#126)
CREATE TABLE security_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    query_json TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    affected_count INTEGER NOT NULL DEFAULT 0,
    resolved_count INTEGER NOT NULL DEFAULT 0
);

-- Supply chain provenance (#29)
CREATE TABLE artifact_provenances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    artifact_name VARCHAR(500) NOT NULL,
    version VARCHAR(100) NOT NULL,
    sbom_id UUID REFERENCES sboms(id) ON DELETE SET NULL,
    signature_json TEXT,
    build_json TEXT,
    provenance_json TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
);

-- Seed compliance frameworks
INSERT INTO compliance_frameworks (id, name, version, description, type, controls_json, mapping_json) VALUES
(gen_random_uuid(), 'OWASP ASVS', '5.0.0', 'Application Security Verification Standard', 'STANDARD', '[{"id":"1.1.1","level":"L1","title":"Verify authentication"},{"id":"2.2.1","level":"L2","title":"Verify anti-automation"}]', '{"cwe":"CWE-287","owasp":"A01:2021"}'),
(gen_random_uuid(), 'OWASP MASVS', '2.0.0', 'Mobile App Security Verification', 'STANDARD', '[{"id":"MSTG-STORAGE-1","title":"Secure storage"},{"id":"MSTG-CRYPTO-1","title":"Crypto"}]', '{"masvs":"MSTG-STORAGE"}'),
(gen_random_uuid(), 'NIST SSDF', '1.1', 'Secure Software Development Framework SP 800-218', 'STANDARD', '[{"id":"PO.1.1","title":"Define Security Requirements"}]', '{}'),
(gen_random_uuid(), 'CIS Benchmark', 'v8', 'CIS Controls', 'STANDARD', '[{"id":"CIS-3.3","title":"Configure Data Protection"}]', '{}'),
(gen_random_uuid(), 'PCI DSS', '4.0', 'Payment Card Industry', 'COMPLIANCE', '[{"id":"6.2","title":"Secure systems"}]', '{}'),
(gen_random_uuid(), 'ISO 27001', '2022', 'Information Security Management', 'COMPLIANCE', '[{"id":"A.8.26","title":"Application security requirements"}]', '{}');
