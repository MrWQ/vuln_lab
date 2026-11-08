"""Add Provider capability revisioning and durable AI review accounting."""
from alembic import op
import sqlalchemy as sa

revision = "0004_ai_review_pipeline"
down_revision = "0003_domain_relations_outbox"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("ai_provider_config")}
    if "configuration_revision" not in columns:
        op.add_column("ai_provider_config", sa.Column("configuration_revision", sa.Integer(), nullable=False,
                                                       server_default="1"))
    if "capability_report" not in columns:
        op.add_column("ai_provider_config", sa.Column("capability_report", sa.JSON(), nullable=False,
                                                       server_default="{}"))
    if "requests_per_minute" not in columns:
        op.add_column("ai_provider_config", sa.Column("requests_per_minute", sa.Integer(), nullable=False,
                                                       server_default="60"))
    if "max_concurrent_reviews" not in columns:
        op.add_column("ai_provider_config", sa.Column("max_concurrent_reviews", sa.Integer(), nullable=False,
                                                       server_default="2"))
    tables = set(sa.inspect(bind).get_table_names())
    if "ai_review_tasks" not in tables:
        op.create_table(
            "ai_review_tasks",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("material_id", sa.String(36), sa.ForeignKey("material_variants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_provider_config.id", ondelete="SET NULL")),
            sa.Column("idempotency_key", sa.String(64), nullable=False, unique=True),
            sa.Column("input_sha256", sa.String(64), nullable=False),
            sa.Column("provider_revision", sa.Integer(), nullable=False),
            sa.Column("rubric_version", sa.String(80), nullable=False),
            sa.Column("prompt_version", sa.String(80), nullable=False),
            sa.Column("state", sa.String(24), nullable=False, server_default="queued"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reserved_cost_usd", sa.Float(), nullable=False, server_default="0"),
            sa.Column("actual_cost_usd", sa.Float(), nullable=False, server_default="0"),
            sa.Column("result_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("last_error", sa.Text()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_ai_review_tasks_material_id", "ai_review_tasks", ["material_id"])
        op.create_index("ix_ai_review_tasks_state", "ai_review_tasks", ["state"])
        op.create_index("ix_ai_review_tasks_available_at", "ai_review_tasks", ["available_at"])
    ai_review_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_reviews")}
    if "task_id" not in ai_review_columns:
        with op.batch_alter_table("ai_reviews") as batch:
            batch.add_column(sa.Column("task_id", sa.String(36), nullable=True))
            batch.create_foreign_key("fk_ai_reviews_task_id", "ai_review_tasks", ["task_id"], ["id"],
                                     ondelete="SET NULL")
        op.create_index("ix_ai_reviews_task_id", "ai_reviews", ["task_id"])
    if "ai_usage_records" not in tables:
        op.create_table(
            "ai_usage_records",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("task_id", sa.String(36), sa.ForeignKey("ai_review_tasks.id", ondelete="CASCADE"), nullable=False),
            sa.Column("attempt", sa.Integer(), nullable=False),
            sa.Column("provider_revision", sa.Integer(), nullable=False),
            sa.Column("model", sa.String(200), nullable=False),
            sa.Column("state", sa.String(24), nullable=False, server_default="reserved"),
            sa.Column("reserved_cost_usd", sa.Float(), nullable=False, server_default="0"),
            sa.Column("actual_cost_usd", sa.Float(), nullable=False, server_default="0"),
            sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_category", sa.String(64)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("settled_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint("task_id", "attempt", name="uq_ai_usage_task_attempt"),
        )
        op.create_index("ix_ai_usage_records_task_id", "ai_usage_records", ["task_id"])
        op.create_index("ix_ai_usage_records_state", "ai_usage_records", ["state"])
        op.create_index("ix_ai_usage_records_created_at", "ai_usage_records", ["created_at"])


def downgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "ai_usage_records" in tables:
        op.drop_table("ai_usage_records")
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_reviews")}
    if "task_id" in columns:
        op.drop_index("ix_ai_reviews_task_id", table_name="ai_reviews")
        with op.batch_alter_table("ai_reviews") as batch:
            batch.drop_column("task_id")
    if "ai_review_tasks" in tables:
        op.drop_table("ai_review_tasks")
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ai_provider_config")}
    if "capability_report" in columns:
        op.drop_column("ai_provider_config", "capability_report")
    if "configuration_revision" in columns:
        op.drop_column("ai_provider_config", "configuration_revision")
    if "max_concurrent_reviews" in columns:
        op.drop_column("ai_provider_config", "max_concurrent_reviews")
    if "requests_per_minute" in columns:
        op.drop_column("ai_provider_config", "requests_per_minute")
