-- V4: One-Click unified test runs
CREATE TABLE IF NOT EXISTS oneclick_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    project_id UUID,
    target VARCHAR(1000) NOT NULL,
    detected_type VARCHAR(50),
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED',
    progress INTEGER NOT NULL DEFAULT 0,
    total_scans INTEGER,
    completed_scans INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER,
    report_id UUID,
    scan_ids_json TEXT,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_oneclick_project ON oneclick_runs(project_id);
