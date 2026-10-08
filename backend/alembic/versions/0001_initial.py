"""Initial schema — all tables, indexes, triggers

Revision ID: 0001_initial
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ── Audit schema (must exist before the table) ────────────────────────────
    op.execute("CREATE SCHEMA IF NOT EXISTS forensics_audit")

    # ── Case number sequence ──────────────────────────────────────────────────
    op.execute("CREATE SEQUENCE IF NOT EXISTS case_number_seq START 1")

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email",         sa.String(255), nullable=False, unique=True),
        sa.Column("full_name",     sa.String(200), nullable=False),
        sa.Column("role",          sa.String(50),  nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active",     sa.Boolean(),   nullable=False, server_default="true"),
        sa.Column("created_at",    sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── cases ─────────────────────────────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_number",      sa.String(50),  nullable=False, unique=True),
        sa.Column("title",            sa.String(300), nullable=False),
        sa.Column("description",      sa.Text(),      nullable=True),
        sa.Column("reference_number", sa.String(100), nullable=True),
        sa.Column("status",           sa.String(20),  nullable=False, server_default="open"),
        sa.Column("created_by",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_cases_status",     "cases", ["status"])
    op.create_index("ix_cases_created_by", "cases", ["created_by"])

    # ── case_assignments ──────────────────────────────────────────────────────
    op.create_table(
        "case_assignments",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assigned_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_user_assignment"),
    )

    # ── evidence ──────────────────────────────────────────────────────────────
    op.create_table(
        "evidence",
        sa.Column("id",                   postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",              postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("filename",             sa.String(500), nullable=False),
        sa.Column("file_size_bytes",      sa.BigInteger(), nullable=False),
        sa.Column("mime_type",            sa.String(200), nullable=False),
        sa.Column("evidence_type",        sa.String(50),  nullable=False),
        sa.Column("sha256_hash",          sa.String(64),  nullable=False),
        sa.Column("storage_key",          sa.String(500), nullable=False),
        sa.Column("hash_source",          sa.String(20),  nullable=False, server_default="computed"),
        sa.Column("acquisition_tool",     sa.String(200), nullable=True),
        sa.Column("description",          sa.Text(),      nullable=False),
        sa.Column("acquisition_notes",    sa.Text(),      nullable=True),
        sa.Column("uploaded_by",          postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("uploaded_at",          sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("current_custodian_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("integrity_status",     sa.String(20), nullable=False, server_default="pending"),
    )
    op.create_index("ix_evidence_case_id", "evidence", ["case_id"])
    # Most critical index — verification portal queries by hash
    op.create_index("ix_evidence_sha256",  "evidence", ["sha256_hash"])

    # ── custody_records ───────────────────────────────────────────────────────
    op.create_table(
        "custody_records",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("evidence_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("evidence.id"), nullable=False),
        sa.Column("from_user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("to_user_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("transfer_reason",  sa.Text(),     nullable=False),
        sa.Column("hash_at_transfer", sa.String(64), nullable=False),
        sa.Column("status",           sa.String(20), nullable=False, server_default="pending"),
        sa.Column("initiated_at",     sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("accepted_at",      sa.DateTime(timezone=True), nullable=True),
        sa.Column("from_signature",   sa.Text(), nullable=False),
        sa.Column("to_signature",     sa.Text(), nullable=True),
    )
    op.create_index("ix_custody_evidence_id", "custody_records", ["evidence_id"])

    # ── tasks ─────────────────────────────────────────────────────────────────
    op.create_table(
        "tasks",
        sa.Column("id",                  postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",             postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("title",               sa.String(300), nullable=False),
        sa.Column("description",         sa.Text(),      nullable=True),
        sa.Column("assigned_to_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assigned_by_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status",              sa.String(20), nullable=False, server_default="assigned"),
        sa.Column("due_date",            sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at",          sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at",          sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tasks_case_id",     "tasks", ["case_id"])
    op.create_index("ix_tasks_assigned_to", "tasks", ["assigned_to_user_id"])

    # ── task_evidence_links ───────────────────────────────────────────────────
    op.create_table(
        "task_evidence_links",
        sa.Column("task_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tasks.id"),    primary_key=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("evidence.id"), primary_key=True),
    )

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("task_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tasks.id"),    nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("evidence.id"), nullable=False),
        sa.Column("title",       sa.String(200), nullable=False),
        sa.Column("content",     sa.Text(),      nullable=False),
        sa.Column("created_by",  postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_findings_task_id", "findings", ["task_id"])

    # ── finding_attachments ───────────────────────────────────────────────────
    op.create_table(
        "finding_attachments",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id",  postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("filename",    sa.String(500), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False),
        sa.Column("sha256_hash", sa.String(64),  nullable=False),
        sa.Column("size_bytes",  sa.BigInteger(), nullable=False),
    )

    # ── reports ───────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id",                  postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",             postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("title",               sa.String(300), nullable=False),
        sa.Column("status",              sa.String(20),  nullable=False, server_default="draft"),
        sa.Column("latest_version",      sa.Integer(),   nullable=False, server_default="1"),
        sa.Column("court_ready_version", sa.Integer(),   nullable=True),
        sa.Column("created_by",          postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_reports_case_id", "reports", ["case_id"])

    # ── report_versions ───────────────────────────────────────────────────────
    op.create_table(
        "report_versions",
        sa.Column("id",             postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("report_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reports.id"), nullable=False),
        sa.Column("version_number", sa.Integer(),   nullable=False),
        sa.Column("content",        sa.Text(),      nullable=False),
        sa.Column("content_hash",   sa.String(64),  nullable=False),
        sa.Column("author_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("saved_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("change_summary", sa.String(500), nullable=False),
        sa.Column("is_court_ready", sa.Boolean(),   nullable=False, server_default="false"),
        sa.Column("locked_by",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("locked_at",      sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_notes",   sa.Text(), nullable=True),
        sa.UniqueConstraint("report_id", "version_number", name="uq_report_version"),
    )
    op.create_index("ix_report_versions_report_id", "report_versions", ["report_id"])

    # ── report link tables ────────────────────────────────────────────────────
    op.create_table(
        "report_evidence_links",
        sa.Column("report_id",   postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reports.id"),  primary_key=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("evidence.id"), primary_key=True),
    )
    op.create_table(
        "report_finding_links",
        sa.Column("report_id",  postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reports.id"),  primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id"), primary_key=True),
    )

    # ── forensics_audit.audit_log ─────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_id",      postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_role",    sa.String(50),  nullable=True),
        sa.Column("action_type",   sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50),  nullable=False),
        sa.Column("resource_id",   sa.String(100), nullable=False),
        sa.Column("ip_address",    sa.String(45),  nullable=False),
        sa.Column("result",        sa.String(20),  nullable=False),
        sa.Column("detail",        postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("timestamp",     sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="forensics_audit",
    )
    op.create_index("ix_audit_actor_id",    "audit_log", ["actor_id"],    schema="forensics_audit")
    op.create_index("ix_audit_action_type", "audit_log", ["action_type"], schema="forensics_audit")
    op.create_index("ix_audit_resource_id", "audit_log", ["resource_id"], schema="forensics_audit")
    op.create_index("ix_audit_timestamp",   "audit_log", ["timestamp"],   schema="forensics_audit")

    # ── DB triggers ───────────────────────────────────────────────────────────

    # Auto-generate case_number
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_case_number()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.case_number := 'CASE-' || TO_CHAR(NOW(), 'YYYY') || '-' ||
                             LPAD(nextval('case_number_seq')::text, 5, '0');
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_case_number
          BEFORE INSERT ON cases
          FOR EACH ROW
          WHEN (NEW.case_number IS NULL OR NEW.case_number = '')
          EXECUTE FUNCTION generate_case_number();
    """)

    # Block UPDATE on accepted custody records
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_custody_update()
        RETURNS TRIGGER AS $$
        BEGIN
          IF OLD.status = 'accepted' THEN
            RAISE EXCEPTION 'Accepted custody records are immutable.';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_custody_immutable
          BEFORE UPDATE ON custody_records
          FOR EACH ROW
          EXECUTE FUNCTION prevent_custody_update();
    """)

    # Block UPDATE on court-ready report versions
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_version_update()
        RETURNS TRIGGER AS $$
        BEGIN
          IF OLD.is_court_ready = TRUE THEN
            RAISE EXCEPTION 'Court-ready report versions are immutable.';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_version_immutable
          BEFORE UPDATE ON report_versions
          FOR EACH ROW
          EXECUTE FUNCTION prevent_version_update();
    """)

    # Block DELETE on evidence
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_evidence_delete()
        RETURNS TRIGGER AS $$
        BEGIN
          RAISE EXCEPTION 'Evidence records cannot be deleted.';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_evidence_nodelete
          BEFORE DELETE ON evidence
          FOR EACH ROW
          EXECUTE FUNCTION prevent_evidence_delete();
    """)

    # Block DELETE on report_versions
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_version_delete()
        RETURNS TRIGGER AS $$
        BEGIN
          RAISE EXCEPTION 'Report versions cannot be deleted.';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER trg_version_nodelete
          BEFORE DELETE ON report_versions
          FOR EACH ROW
          EXECUTE FUNCTION prevent_version_delete();
    """)

    # ── DB role permissions ───────────────────────────────────────────────────
    op.execute("""
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'forensics_app') THEN
            CREATE ROLE forensics_app LOGIN PASSWORD 'forensics_app_secret';
          END IF;
        END $$;
    """)
    op.execute("GRANT USAGE ON SCHEMA public TO forensics_app")
    op.execute("GRANT USAGE ON SCHEMA forensics_audit TO forensics_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO forensics_app")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO forensics_app")
    op.execute("GRANT INSERT, SELECT ON forensics_audit.audit_log TO forensics_app")

    # ── Seed admin user ───────────────────────────────────────────────────────
    op.execute("""
        INSERT INTO users (id, email, full_name, role, password_hash, is_active, created_at)
        VALUES (
            gen_random_uuid(),
            'admin@forensicchain.dev',
            'System Administrator',
            'Admin',
            crypt('Admin@Forensics123', gen_salt('bf', 12)),
            TRUE,
            NOW()
        ) ON CONFLICT (email) DO NOTHING;
    """)


def downgrade() -> None:
    # Drop triggers first
    for trigger, table in [
        ("trg_case_number",       "cases"),
        ("trg_custody_immutable", "custody_records"),
        ("trg_version_immutable", "report_versions"),
        ("trg_evidence_nodelete", "evidence"),
        ("trg_version_nodelete",  "report_versions"),
    ]:
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")

    for fn in [
        "generate_case_number", "prevent_custody_update",
        "prevent_version_update", "prevent_evidence_delete", "prevent_version_delete",
    ]:
        op.execute(f"DROP FUNCTION IF EXISTS {fn}()")

    # Drop tables in reverse FK order
    for t in [
        "report_finding_links", "report_evidence_links", "report_versions", "reports",
        "finding_attachments", "findings", "task_evidence_links", "tasks",
        "custody_records", "evidence", "case_assignments", "cases", "users",
    ]:
        op.drop_table(t)

    op.drop_table("audit_log", schema="forensics_audit")
    op.execute("DROP SCHEMA IF EXISTS forensics_audit")
    op.execute("DROP SEQUENCE IF EXISTS case_number_seq")
