"""Use a valid development email for the seeded admin account."""

from alembic import op

revision = "0003_fix_admin_email"
down_revision = "0002_fix_admin_password"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE users
        SET email = 'admin@forensicchain.dev'
        WHERE email = 'admin@forensics.local'
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE users
        SET email = 'admin@forensics.local'
        WHERE email = 'admin@forensicchain.dev'
        """
    )
