ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_type VARCHAR(50);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS security_vulnerability BOOLEAN DEFAULT true;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vulnerability_confirmed BOOLEAN DEFAULT false;

UPDATE findings SET finding_type = 'VULNERABILITY' WHERE finding_type IS NULL;
UPDATE findings SET security_vulnerability = true WHERE security_vulnerability IS NULL;
UPDATE findings SET vulnerability_confirmed = true WHERE vulnerability_confirmed IS NULL AND cwe IS NOT NULL;
UPDATE findings SET vulnerability_confirmed = false WHERE vulnerability_confirmed IS NULL AND cwe IS NULL;
