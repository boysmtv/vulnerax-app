-- V2: Add remaining tables not in V1

-- Cloud resources
CREATE TABLE IF NOT EXISTS cloud_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    region VARCHAR(100),
    identifier VARCHAR(500),
    configuration JSONB DEFAULT '{}',
    risk_level VARCHAR(20) DEFAULT 'LOW'
);

-- K8s resources
CREATE TABLE IF NOT EXISTS k8s_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    namespace VARCHAR(255),
    kind VARCHAR(100) NOT NULL,
    cluster_name VARCHAR(255),
    risks_json TEXT DEFAULT '[]'
);

-- IaC scans
CREATE TABLE IF NOT EXISTS iac_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    file_name VARCHAR(500) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    issues_json TEXT DEFAULT '[]'
);

-- Network assets
CREATE TABLE IF NOT EXISTS network_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hostname VARCHAR(255),
    ip_address VARCHAR(50),
    open_ports TEXT DEFAULT '[]',
    services TEXT DEFAULT '[]',
    vulnerabilities TEXT DEFAULT '[]'
);

-- Database assets
CREATE TABLE IF NOT EXISTS database_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    db_type VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    host VARCHAR(255),
    port INTEGER,
    exposed BOOLEAN DEFAULT FALSE,
    vulnerabilities TEXT DEFAULT '[]'
);

-- CI/CD pipelines
CREATE TABLE IF NOT EXISTS cicd_pipelines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    repository_url VARCHAR(500),
    branch VARCHAR(255),
    status VARCHAR(50) DEFAULT 'UNKNOWN',
    last_run_at TIMESTAMPTZ,
    vulnerabilities TEXT DEFAULT '[]'
);

-- IAM resources
CREATE TABLE IF NOT EXISTS iam_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    identifier VARCHAR(500),
    policies TEXT DEFAULT '[]',
    risks TEXT DEFAULT '[]'
);

-- Container images
CREATE TABLE IF NOT EXISTS container_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    tag VARCHAR(255),
    registry VARCHAR(255),
    os VARCHAR(100),
    vulnerabilities TEXT DEFAULT '[]',
    layers INTEGER DEFAULT 0
);

-- AI assets
CREATE TABLE IF NOT EXISTS ai_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    model_type VARCHAR(100) NOT NULL,
    provider VARCHAR(100),
    endpoint VARCHAR(500),
    risks TEXT DEFAULT '[]'
);

-- Browser extensions
CREATE TABLE IF NOT EXISTS browser_extensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    browser VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    permissions TEXT DEFAULT '[]',
    risks TEXT DEFAULT '[]'
);

-- Firmware assets
CREATE TABLE IF NOT EXISTS firmware_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(100),
    version VARCHAR(50),
    file_hash VARCHAR(256),
    vulnerabilities TEXT DEFAULT '[]'
);

-- SBOMs
CREATE TABLE IF NOT EXISTS sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL DEFAULT 'CycloneDX',
    content JSONB,
    component_count INTEGER DEFAULT 0,
    vulnerability_count INTEGER DEFAULT 0
);

-- Mobile analyses
CREATE TABLE IF NOT EXISTS mobile_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    app_name VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    version VARCHAR(50),
    package_name VARCHAR(255),
    issues_json TEXT DEFAULT '[]'
);
