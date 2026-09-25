-- ─────────────────────────────────────────────────────────────────────────────
-- Forensics DB initialisation
-- Run once by Docker entrypoint on first start.
-- ─────────────────────────────────────────────────────────────────────────────

-- Separate schema for the audit log — restricted access
CREATE SCHEMA IF NOT EXISTS forensics_audit;

-- ── App DB role (used by the FastAPI app) ─────────────────────────────────────
-- This role has NO DELETE or UPDATE on audit_log or custody_records (once accepted)
-- and NO DELETE on evidence or report_versions — immutability enforced at DB level.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'forensics_app') THEN
    CREATE ROLE forensics_app LOGIN PASSWORD 'forensics_app_secret';
  END IF;
END $$;

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO forensics_app;
GRANT USAGE ON SCHEMA forensics_audit TO forensics_app;

-- Full access to main tables (restrictions added below per table)
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO forensics_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO forensics_app;

-- ── Audit log: INSERT only — no UPDATE, no DELETE ─────────────────────────────
GRANT INSERT, SELECT ON forensics_audit.audit_log TO forensics_app;
-- UPDATE and DELETE are deliberately NOT granted.

-- ── Case number sequence ──────────────────────────────────────────────────────
CREATE SEQUENCE IF NOT EXISTS case_number_seq START 1;

-- ── Function: auto-generate case_number ──────────────────────────────────────
CREATE OR REPLACE FUNCTION generate_case_number()
RETURNS TRIGGER AS $$
BEGIN
  NEW.case_number := 'CASE-' || TO_CHAR(NOW(), 'YYYY') || '-' ||
                     LPAD(nextval('case_number_seq')::text, 5, '0');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_case_number
  BEFORE INSERT ON cases
  FOR EACH ROW
  WHEN (NEW.case_number IS NULL OR NEW.case_number = '')
  EXECUTE FUNCTION generate_case_number();

-- ── Function: block UPDATE on accepted custody records ────────────────────────
-- Once a custody transfer is accepted, it must never change.
CREATE OR REPLACE FUNCTION prevent_custody_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status = 'accepted' THEN
    RAISE EXCEPTION 'Accepted custody records are immutable.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_custody_immutable
  BEFORE UPDATE ON custody_records
  FOR EACH ROW
  EXECUTE FUNCTION prevent_custody_update();

-- ── Function: block UPDATE on court-ready report versions ────────────────────
CREATE OR REPLACE FUNCTION prevent_version_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.is_court_ready = TRUE THEN
    RAISE EXCEPTION 'Court-ready report versions are immutable.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_version_immutable
  BEFORE UPDATE ON report_versions
  FOR EACH ROW
  EXECUTE FUNCTION prevent_version_update();

-- ── Function: block DELETE on evidence ───────────────────────────────────────
CREATE OR REPLACE FUNCTION prevent_evidence_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Evidence records cannot be deleted.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_evidence_nodelete
  BEFORE DELETE ON evidence
  FOR EACH ROW
  EXECUTE FUNCTION prevent_evidence_delete();

-- ── Function: block DELETE on report_versions ────────────────────────────────
CREATE OR REPLACE FUNCTION prevent_version_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Report versions cannot be deleted — required for legal traceability.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_version_nodelete
  BEFORE DELETE ON report_versions
  FOR EACH ROW
  EXECUTE FUNCTION prevent_version_delete();

-- ── Indexes for verification portal (hot path) ────────────────────────────────
-- Already declared in SQLAlchemy models, but listed here for clarity:
-- CREATE INDEX ix_evidence_sha256 ON evidence(sha256_hash);
-- This index is what makes the public /verify/{hash} endpoint fast.

-- ── Seed: admin user (change password immediately in production) ───────────────
-- Password: Admin@Forensics123  (bcrypt hash below — regenerate for real deployments)
INSERT INTO users (id, email, full_name, role, password_hash, is_active, created_at)
VALUES (
  gen_random_uuid(),
  'admin@forensics.local',
  'System Administrator',
  'Admin',
  '$2b$12$placeholder_bcrypt_hash_change_this',
  TRUE,
  NOW()
) ON CONFLICT (email) DO NOTHING;
