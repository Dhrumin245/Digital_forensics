"""Repair the local development admin password seed."""

from alembic import op

revision = "0002_fix_admin_password"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        UPDATE users
        SET password_hash = crypt('Admin@Forensics123', gen_salt('bf', 12))
        WHERE email = 'admin@forensicchain.dev'
          AND password_hash LIKE '%CHANGEME%'
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE users
        SET password_hash = '$2b$12$CHANGEME_run_python_hash_password_to_generate'
        WHERE email = 'admin@forensicchain.dev'
        """
    )
