"""Add worker lease fencing token."""
from alembic import op
import sqlalchemy as sa

revision = "0002_job_lease_token"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("jobs")}
    if "lease_token" not in columns:
        op.add_column("jobs", sa.Column("lease_token", sa.String(length=64), nullable=True))
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("jobs")}
    if "ix_jobs_lease_token" not in indexes:
        op.create_index("ix_jobs_lease_token", "jobs", ["lease_token"], unique=False)


def downgrade():
    bind = op.get_bind()
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("jobs")}
    if "ix_jobs_lease_token" in indexes:
        op.drop_index("ix_jobs_lease_token", table_name="jobs")
    columns = {column["name"] for column in sa.inspect(bind).get_columns("jobs")}
    if "lease_token" in columns:
        op.drop_column("jobs", "lease_token")
