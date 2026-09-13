-- VulneraX V1: Initial Schema
-- All tables use UUID primary keys

-- ============================================
-- IDENTITY & AUTH
-- ============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'DEVELOPER',
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    sso_provider VARCHAR(50),
    active BOOLEAN NOT NULL DEFAULT true,
    organization_id UUID,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(100) NOT NULL,
    PRIMARY KEY (user_id, role)
);

-- ============================================
-- ORGANIZATION
-- ============================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    tier VARCHAR(50) NOT NULL DEFAULT 'ENTERPRISE',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    repository_url VARCHAR(500),
    language VARCHAR(50),
    framework VARCHAR(100),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- RBAC
-- ============================================
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role VARCHAR(50) NOT NULL,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role, permission_id)
);

-- ============================================
-- ASSETS
-- ============================================
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    url VARCHAR(500),
    environment VARCHAR(50) DEFAULT 'PRODUCTION',
    criticality VARCHAR(50) DEFAULT 'MEDIUM',
    tags JSONB,
    metadata JSONB,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_assets_project ON assets(project_id);
CREATE INDEX idx_assets_type ON assets(type);

-- ============================================
-- FINDINGS
-- ============================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
    project_id UUID,
    asset_id UUID,
    asset_name VARCHAR(255),
    environment VARCHAR(50),
    source VARCHAR(100),
    scan_id UUID,
    cwe VARCHAR(50),
    owasp VARCHAR(50),
    masvs VARCHAR(50),
    asvs VARCHAR(50),
    cvss DOUBLE PRECISION,
    epss DOUBLE PRECISION,
    kev BOOLEAN DEFAULT false,
    internet_exposed BOOLEAN DEFAULT false,
    reachable BOOLEAN DEFAULT false,
    business_criticality VARCHAR(50),
    owner VARCHAR(255),
    file_path VARCHAR(500),
    line_number INTEGER,
    function_name VARCHAR(255),
    code_snippet TEXT,
    data_flow TEXT,
    recommendation TEXT,
    risk_score DOUBLE PRECISION,
    risk_level VARCHAR(50),
    fingerprint VARCHAR(100),
    false_positive BOOLEAN DEFAULT false,
    duplicate BOOLEAN DEFAULT false,
    parent_finding_id UUID,
    sla_due_at TIMESTAMP,
    sla_status VARCHAR(50) DEFAULT 'WITHIN_SLA',
    organization_id UUID,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_asset ON findings(asset_id);
CREATE INDEX idx_findings_org ON findings(organization_id);

-- ============================================
-- EVIDENCES
-- ============================================
CREATE TABLE evidences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL,
    asset_id UUID,
    scan_id UUID,
    type VARCHAR(50) NOT NULL,
    content TEXT,
    file_name VARCHAR(255),
    mime_type VARCHAR(100),
    sha256 VARCHAR(64),
    author VARCHAR(255),
    sensitive BOOLEAN DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidences_finding ON evidences(finding_id);

-- ============================================
-- FINDING INSTANCES
-- ============================================
CREATE TABLE finding_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL,
    asset_name VARCHAR(255) NOT NULL,
    location VARCHAR(500),
    scanner VARCHAR(100),
    evidence TEXT,
    fingerprint VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_finding_instances_finding ON finding_instances(finding_id);

-- ============================================
-- SCANS
-- ============================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    asset_id UUID,
    profile VARCHAR(50) NOT NULL,
    scanner_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'QUEUED',
    target VARCHAR(500),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    initiated_by VARCHAR(255),
    config_json TEXT,
    scope_json TEXT,
    findings_count INTEGER,
    duration_ms BIGINT,
    organization_id UUID,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_scans_project ON scans(project_id);

-- ============================================
-- SCAN JOBS
-- ============================================
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL,
    scanner_plugin VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'QUEUED',
    progress INTEGER DEFAULT 0,
    worker_id VARCHAR(100),
    result_json TEXT,
    logs TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_jobs_scan ON scan_jobs(scan_id);

-- ============================================
-- AUDIT
-- ============================================
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id VARCHAR(100),
    actor VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_action ON audit_events(action);

-- ============================================
-- REPORTS
-- ============================================
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    title VARCHAR(500) NOT NULL,
    type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL DEFAULT 'PDF',
    status VARCHAR(50) NOT NULL DEFAULT 'GENERATING',
    file_path VARCHAR(500),
    generated_by VARCHAR(255),
    parameters TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- NOTIFICATIONS
-- ============================================
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    read BOOLEAN DEFAULT false,
    action_url VARCHAR(500),
    entity_type VARCHAR(100),
    entity_id UUID,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_notifications_user ON notifications(user_id);

-- ============================================
-- INTEGRATIONS
-- ============================================
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    config JSONB,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- COMPLIANCE
-- ============================================
CREATE TABLE compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    project_id UUID NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'NOT_STARTED',
    score DOUBLE PRECISION,
    assessed_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- POLICIES
-- ============================================
CREATE TABLE security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rules TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE policy_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    finding_id UUID,
    reason TEXT NOT NULL,
    approved_by VARCHAR(255),
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- THREAT MODELS
-- ============================================
CREATE TABLE threat_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    model_data TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- PENTEST
-- ============================================
CREATE TABLE pentest_engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PLANNED',
    pentester VARCHAR(255),
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    scope TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- RETEST
-- ============================================
CREATE TABLE retests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    retester VARCHAR(255),
    result VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_retests_finding ON retests(finding_id);

-- ============================================
-- SUPPLY CHAIN
-- ============================================
CREATE TABLE artifact_provenances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    artifact_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    source VARCHAR(255),
    hash VARCHAR(255),
    signature_valid BOOLEAN,
    verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- COVERAGE
-- ============================================
CREATE TABLE security_coverages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    category VARCHAR(100) NOT NULL,
    percentage DOUBLE PRECISION DEFAULT 0,
    tested_count INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- CAMPAIGNS
-- ============================================
CREATE TABLE security_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'PLANNED',
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- ============================================
-- SEED DATA: Default permissions
-- ============================================
INSERT INTO permissions (name, resource, action, description) VALUES
('FINDINGS_READ', 'findings', 'read', 'View findings'),
('FINDINGS_WRITE', 'findings', 'write', 'Create and edit findings'),
('FINDINGS_DELETE', 'findings', 'delete', 'Delete findings'),
('FINDINGS_APPROVE', 'findings', 'approve', 'Approve findings status changes'),
('SCANS_READ', 'scans', 'read', 'View scans'),
('SCANS_WRITE', 'scans', 'write', 'Create and manage scans'),
('SCANS_CANCEL', 'scans', 'cancel', 'Cancel running scans'),
('ASSETS_READ', 'assets', 'read', 'View assets'),
('ASSETS_WRITE', 'assets', 'write', 'Create and manage assets'),
('REPORTS_READ', 'reports', 'read', 'View reports'),
('REPORTS_WRITE', 'reports', 'write', 'Generate reports'),
('ORG_READ', 'organizations', 'read', 'View organizations'),
('ORG_WRITE', 'organizations', 'write', 'Manage organizations'),
('POLICY_READ', 'policies', 'read', 'View policies'),
('POLICY_WRITE', 'policies', 'write', 'Manage policies'),
('COMPLIANCE_READ', 'compliance', 'read', 'View compliance'),
('COMPLIANCE_WRITE', 'compliance', 'write', 'Manage compliance assessments'),
('AUDIT_READ', 'audit', 'read', 'View audit logs'),
('SETTINGS_READ', 'settings', 'read', 'View settings'),
('SETTINGS_WRITE', 'settings', 'write', 'Manage settings'),
('USERS_READ', 'users', 'read', 'View users'),
('USERS_WRITE', 'users', 'write', 'Manage users'),
('INTEGRATIONS_READ', 'integrations', 'read', 'View integrations'),
('INTEGRATIONS_WRITE', 'integrations', 'write', 'Manage integrations');

-- ============================================
-- SEED DATA: Default role-permission mapping
-- ============================================
-- ORG_OWNER: full access
INSERT INTO role_permissions (role, permission_id)
SELECT 'ORG_OWNER', id FROM permissions;

-- SECURITY_ADMIN: all except ORG settings
INSERT INTO role_permissions (role, permission_id)
SELECT 'SECURITY_ADMIN', id FROM permissions WHERE name NOT IN ('ORG_WRITE', 'SETTINGS_WRITE', 'USERS_WRITE');

-- SECURITY_ENGINEER: findings + scans + assets + reports
INSERT INTO role_permissions (role, permission_id)
SELECT 'SECURITY_ENGINEER', id FROM permissions WHERE resource IN ('findings', 'scans', 'assets', 'reports', 'compliance');

-- PENTESTER: findings + scans (read/write)
INSERT INTO role_permissions (role, permission_id)
SELECT 'PENTESTER', id FROM permissions WHERE resource IN ('findings', 'scans') AND action IN ('read', 'write');

-- DEVELOPER: findings read, scans read, assets read
INSERT INTO role_permissions (role, permission_id)
SELECT 'DEVELOPER', id FROM permissions WHERE resource IN ('findings', 'scans', 'assets') AND action = 'read';

-- AUDITOR: read-only everything
INSERT INTO role_permissions (role, permission_id)
SELECT 'AUDITOR', id FROM permissions WHERE action = 'read';

-- VIEWER: minimal read
INSERT INTO role_permissions (role, permission_id)
SELECT 'VIEWER', id FROM permissions WHERE resource IN ('findings', 'scans', 'assets', 'reports') AND action = 'read';
