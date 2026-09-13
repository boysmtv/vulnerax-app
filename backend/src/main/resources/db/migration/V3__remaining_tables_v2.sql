-- V3: Fix remaining tables - drop V2 wrong schemas, recreate correctly per JPA entities

-- ============================================
-- 1. FIX role_permissions - add id column (JPA expects single PK)
-- ============================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='role_permissions' AND column_name='id') THEN
        ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_pkey;
        ALTER TABLE role_permissions ADD COLUMN id BIGSERIAL PRIMARY KEY;
        ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_role_perm UNIQUE (role, permission_id);
    END IF;
END $$;

-- ============================================
-- 2. FIX artifact_provenances - add missing columns from entity
-- ============================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='artifact_provenances' AND column_name='project_id') THEN
        ALTER TABLE artifact_provenances ADD COLUMN IF NOT EXISTS sbom_id UUID;
        ALTER TABLE artifact_provenances ADD COLUMN IF NOT EXISTS signature_json TEXT;
        ALTER TABLE artifact_provenances ADD COLUMN IF NOT EXISTS build_json TEXT;
        ALTER TABLE artifact_provenances ADD COLUMN IF NOT EXISTS provenance_json TEXT;
        ALTER TABLE artifact_provenances ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'ACTIVE';
        -- Rename signature_valid -> verified if exists
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='artifact_provenances' AND column_name='signature_valid') THEN
            ALTER TABLE artifact_provenances RENAME COLUMN signature_valid TO verified;
        END IF;
        -- Drop source/hash/verified_at if they exist (not in entity)
        ALTER TABLE artifact_provenances DROP COLUMN IF EXISTS source;
        ALTER TABLE artifact_provenances DROP COLUMN IF EXISTS hash;
        ALTER TABLE artifact_provenances DROP COLUMN IF EXISTS verified_at;
    END IF;
END $$;

-- ============================================
-- 3. DROP V2 wrong tables and recreate correctly
-- ============================================

-- Cloud resources
DROP TABLE IF EXISTS cloud_resources CASCADE;
CREATE TABLE cloud_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    provider VARCHAR(100) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100) NOT NULL,
    service VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(500) NOT NULL,
    name VARCHAR(255),
    configuration_json TEXT,
    risk_json TEXT,
    compliance_json TEXT,
    public_exposed BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- K8s resources
DROP TABLE IF EXISTS k8s_resources CASCADE;
CREATE TABLE k8s_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    cluster_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) DEFAULT 'default',
    kind VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    configuration_json TEXT,
    risk_json TEXT,
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Browser extensions
DROP TABLE IF EXISTS browser_extensions CASCADE;
CREATE TABLE browser_extensions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    manifest_json TEXT NOT NULL,
    permissions_json TEXT DEFAULT '[]',
    findings_json TEXT DEFAULT '[]',
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- AI assets
DROP TABLE IF EXISTS ai_assets CASCADE;
CREATE TABLE ai_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    model VARCHAR(255),
    provider VARCHAR(255),
    endpoints_json TEXT DEFAULT '[]',
    ragn_json TEXT,
    findings_json TEXT DEFAULT '[]',
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Container images
DROP TABLE IF EXISTS container_images CASCADE;
CREATE TABLE container_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    image_name VARCHAR(255) NOT NULL,
    tag VARCHAR(255) DEFAULT 'latest',
    digest VARCHAR(500),
    base_image VARCHAR(500),
    dockerfile TEXT,
    packages_json TEXT DEFAULT '[]',
    cve_json TEXT DEFAULT '[]',
    misconfig_json TEXT DEFAULT '[]',
    secret_json TEXT DEFAULT '[]',
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Database assets
DROP TABLE IF EXISTS database_assets CASCADE;
CREATE TABLE database_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    engine VARCHAR(100) NOT NULL,
    version VARCHAR(50),
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    exposure_json TEXT,
    encryption_json TEXT,
    auth_json TEXT,
    audit_json TEXT,
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Network assets
DROP TABLE IF EXISTS network_assets CASCADE;
CREATE TABLE network_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(50),
    port INTEGER NOT NULL,
    service VARCHAR(255),
    version VARCHAR(100),
    protocol VARCHAR(20) DEFAULT 'TCP',
    tls_json TEXT,
    cert_json TEXT,
    vuln_json TEXT,
    status VARCHAR(50) DEFAULT 'OPEN'
);

-- IaC scans
DROP TABLE IF EXISTS iac_scans CASCADE;
CREATE TABLE iac_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    repository VARCHAR(500),
    file_path VARCHAR(500) NOT NULL,
    tool VARCHAR(50) DEFAULT 'CHECKOV',
    findings_json TEXT DEFAULT '[]',
    passed INTEGER DEFAULT 0,
    failed INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'COMPLETED'
);

-- CI/CD pipelines
DROP TABLE IF EXISTS cicd_pipelines CASCADE;
CREATE TABLE cicd_pipelines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    platform VARCHAR(100) NOT NULL,
    repository VARCHAR(500) NOT NULL,
    pipeline_name VARCHAR(255) NOT NULL,
    configuration_json TEXT,
    findings_json TEXT DEFAULT '[]',
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- IAM resources
DROP TABLE IF EXISTS iam_resources CASCADE;
CREATE TABLE iam_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    provider VARCHAR(100) DEFAULT 'AWS',
    principal_type VARCHAR(100) NOT NULL,
    principal_name VARCHAR(255) NOT NULL,
    policies_json TEXT DEFAULT '[]',
    permissions_json TEXT DEFAULT '[]',
    risk_json TEXT DEFAULT '{}',
    is_excessive BOOLEAN DEFAULT FALSE,
    is_dormant BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Firmware assets
DROP TABLE IF EXISTS firmware_assets CASCADE;
CREATE TABLE firmware_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    file_name VARCHAR(500) NOT NULL,
    file_size BIGINT,
    sha256 VARCHAR(500),
    filesystem_json TEXT,
    binaries_json TEXT DEFAULT '[]',
    cve_json TEXT DEFAULT '[]',
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

-- Mobile analyses
DROP TABLE IF EXISTS mobile_analyses CASCADE;
CREATE TABLE mobile_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    asset_id UUID,
    platform VARCHAR(50) NOT NULL,
    file_name VARCHAR(500) NOT NULL,
    file_sha256 VARCHAR(500),
    file_size BIGINT,
    manifest_json TEXT,
    strings_json TEXT,
    findings_json TEXT,
    cert_info TEXT,
    masvs_score INTEGER DEFAULT 0,
    status VARCHAR(50)
);

-- SBOMs
DROP TABLE IF EXISTS sboms CASCADE;
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID NOT NULL,
    asset_id UUID,
    format VARCHAR(50) NOT NULL,
    version VARCHAR(50) NOT NULL,
    content_json TEXT,
    component_count INTEGER DEFAULT 0,
    vulnerable_count INTEGER DEFAULT 0
);
