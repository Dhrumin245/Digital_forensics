-- Pre-migration database setup.
-- Alembic creates tables, triggers, permissions, and seed data after PostgreSQL
-- becomes healthy. This script must not reference application tables yet.
CREATE SCHEMA IF NOT EXISTS forensics_audit;
-- The application role and grants are created by the Alembic migration after
-- the tables exist.