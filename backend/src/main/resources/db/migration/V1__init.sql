-- VulneraX Platform - Initial Schema V1
-- Modular Monolith + PostgreSQL

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'DEVELOPER',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(100) NOT NULL,
    PRIMARY KEY (user_id, role)
);

-- organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    tier VARCHAR(50) NOT NULL DEFAULT 'ENTERPRISE',
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- workspaces
CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    description TEXT,
    environment VARCHAR(50) NOT NULL DEFAULT 'PRODUCTION'
);

-- projects
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    name VARCHAR(255) NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    description TEXT,
    criticality VARCHAR(20) NOT NULL DEFAULT 'HIGH',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    business_unit VARCHAR(255),
    tech_lead VARCHAR(255),
    security_champion VARCHAR(255)
);

-- assets
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    identifier VARCHAR(500),
    version VARCHAR(100),
    environment VARCHAR(50) NOT NULL DEFAULT 'PRODUCTION',
    criticality VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    data_classification VARCHAR(50) NOT NULL DEFAULT 'INTERNAL',
    internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    managed BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    technology VARCHAR(100) NOT NULL DEFAULT 'UNKNOWN',
    owner VARCHAR(255),
    team VARCHAR(255),
    location VARCHAR(255),
    tags TEXT,
    metadata_json TEXT,
    discovery_source VARCHAR(100)
);
CREATE INDEX idx_assets_project ON assets(project_id);
CREATE INDEX idx_assets_type ON assets(type);

-- scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    profile VARCHAR(50) NOT NULL DEFAULT 'STANDARD',
    scanner_type VARCHAR(50) NOT NULL DEFAULT 'SAST',
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED',
    target VARCHAR(500),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    initiated_by VARCHAR(255),
    config_json TEXT,
    scope_json TEXT,
    findings_count INTEGER,
    duration_ms BIGINT
);
CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);

CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner_plugin VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED',
    worker_id VARCHAR(100),
    logs TEXT,
    progress INTEGER NOT NULL DEFAULT 0,
    result_json TEXT,
    error TEXT
);

-- findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_id VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    asset_name VARCHAR(255),
    environment VARCHAR(50),
    source VARCHAR(100),
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    cwe VARCHAR(20),
    owasp VARCHAR(50),
    masvs VARCHAR(50),
    asvs VARCHAR(50),
    cvss DOUBLE PRECISION,
    epss DOUBLE PRECISION,
    kev BOOLEAN NOT NULL DEFAULT FALSE,
    internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    reachable BOOLEAN NOT NULL DEFAULT FALSE,
    business_criticality VARCHAR(20),
    owner VARCHAR(255),
    file_path VARCHAR(500),
    line_number INTEGER,
    function_name VARCHAR(255),
    code_snippet TEXT,
    data_flow TEXT,
    recommendation TEXT,
    risk_score DOUBLE PRECISION,
    risk_level VARCHAR(20),
    fingerprint VARCHAR(100),
    false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate BOOLEAN NOT NULL DEFAULT FALSE,
    parent_finding_id UUID,
    sla_due_at TIMESTAMPTZ,
    sla_status VARCHAR(20)
);
CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);

CREATE TABLE finding_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_name VARCHAR(255) NOT NULL,
    location VARCHAR(500),
    scanner VARCHAR(100),
    evidence TEXT,
    fingerprint VARCHAR(100)
);

CREATE TABLE evidences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL,
    content TEXT,
    file_name VARCHAR(255),
    mime_type VARCHAR(100),
    sha256 VARCHAR(100),
    author VARCHAR(255),
    sensitive BOOLEAN NOT NULL DEFAULT FALSE
);

-- audit
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id VARCHAR(100),
    actor VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(50)
);

-- reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    format VARCHAR(20) NOT NULL DEFAULT 'PDF',
    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
    content_json TEXT,
    generated_by VARCHAR(255),
    file_path VARCHAR(500),
    classification VARCHAR(50) NOT NULL DEFAULT 'CONFIDENTIAL'
);

-- sboms
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    format VARCHAR(20) NOT NULL DEFAULT 'CYCLONEDX',
    version VARCHAR(100) NOT NULL,
    content_json TEXT,
    component_count INTEGER NOT NULL DEFAULT 0,
    vulnerable_count INTEGER NOT NULL DEFAULT 0
);

-- mobile
CREATE TABLE mobile_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    platform VARCHAR(20) NOT NULL DEFAULT 'ANDROID',
    file_name VARCHAR(255) NOT NULL,
    file_sha256 VARCHAR(100),
    file_size BIGINT,
    manifest_json TEXT,
    strings_json TEXT,
    findings_json TEXT,
    cert_info TEXT,
    masvs_score INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED'
);

-- search index helper (simple)
CREATE INDEX idx_findings_title ON findings(title);
CREATE INDEX idx_assets_name ON assets(name);
