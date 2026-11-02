"""Add normalized aliases, material applicability, object inventory and outbox."""
from alembic import op
import sqlalchemy as sa

revision = "0003_domain_relations_outbox"
down_revision = "0002_job_lease_token"
branch_labels = None
depends_on = None


def _tables():
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade():
    bind = op.get_bind()
    tables = _tables()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("knowledge_entries")}
    if "publication_revision" not in columns:
        op.add_column("knowledge_entries", sa.Column("publication_revision", sa.Integer(), nullable=False,
                                                        server_default="1"))

    if "organization_aliases" not in tables:
        op.create_table(
            "organization_aliases",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("alias", sa.String(240), nullable=False),
            sa.Column("normalized_alias", sa.String(240), nullable=False),
            sa.Column("evidence_json", sa.JSON(), nullable=False),
            sa.UniqueConstraint("organization_id", "normalized_alias", name="uq_organization_alias_normalized"),
        )
        op.create_index("ix_organization_aliases_organization_id", "organization_aliases", ["organization_id"])
        op.create_index("ix_organization_aliases_normalized_alias", "organization_aliases", ["normalized_alias"])

    if "product_aliases" not in tables:
        op.create_table(
            "product_aliases",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="CASCADE"), nullable=False),
            sa.Column("alias", sa.String(300), nullable=False),
            sa.Column("normalized_alias", sa.String(300), nullable=False),
            sa.Column("evidence_json", sa.JSON(), nullable=False),
            sa.UniqueConstraint("product_id", "normalized_alias", name="uq_product_alias_normalized"),
        )
        op.create_index("ix_product_aliases_product_id", "product_aliases", ["product_id"])
        op.create_index("ix_product_aliases_normalized_alias", "product_aliases", ["normalized_alias"])

    if "product_identifiers" not in tables:
        op.create_table(
            "product_identifiers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="CASCADE"), nullable=False),
            sa.Column("namespace", sa.String(120), nullable=False),
            sa.Column("value", sa.String(500), nullable=False),
            sa.Column("evidence_json", sa.JSON(), nullable=False),
            sa.UniqueConstraint("namespace", "value", name="uq_product_identifier"),
        )
        op.create_index("ix_product_identifiers_product_id", "product_identifiers", ["product_id"])

    if "object_blobs" not in tables:
        op.create_table(
            "object_blobs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("namespace", sa.String(24), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("object_key", sa.String(500), nullable=False, unique=True),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("namespace", "sha256", name="uq_object_namespace_sha256"),
        )
        op.create_index("ix_object_blobs_namespace", "object_blobs", ["namespace"])
        op.create_index("ix_object_blobs_sha256", "object_blobs", ["sha256"])

    if "product_material_applicability" not in tables:
        op.create_table(
            "product_material_applicability",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("material_id", sa.String(36), sa.ForeignKey("material_variants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id", ondelete="CASCADE"), nullable=False),
            sa.Column("version_expression", sa.String(500), nullable=True),
            sa.Column("version_status", sa.String(32), nullable=False),
            sa.Column("evidence_refs", sa.JSON(), nullable=False),
            sa.UniqueConstraint("material_id", "product_id", name="uq_material_product_applicability"),
        )
        op.create_index("ix_product_material_applicability_material_id", "product_material_applicability", ["material_id"])
        op.create_index("ix_product_material_applicability_product_id", "product_material_applicability", ["product_id"])

    if "publication_outbox" not in tables:
        op.create_table(
            "publication_outbox",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("entry_id", sa.String(36), sa.ForeignKey("knowledge_entries.id", ondelete="CASCADE"), nullable=False),
            sa.Column("publication_revision", sa.Integer(), nullable=False),
            sa.Column("event_type", sa.String(40), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("state", sa.String(24), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("entry_id", "publication_revision", name="uq_publication_outbox_revision"),
        )
        op.create_index("ix_publication_outbox_entry_id", "publication_outbox", ["entry_id"])
        op.create_index("ix_publication_outbox_state", "publication_outbox", ["state"])
        op.create_index("ix_publication_outbox_state_created", "publication_outbox", ["state", "created_at"])


def downgrade():
    tables = _tables()
    if "publication_outbox" in tables:
        op.drop_table("publication_outbox")
    if "product_material_applicability" in tables:
        op.drop_table("product_material_applicability")
    if "object_blobs" in tables:
        op.drop_table("object_blobs")
    if "product_identifiers" in tables:
        op.drop_table("product_identifiers")
    if "product_aliases" in tables:
        op.drop_table("product_aliases")
    if "organization_aliases" in tables:
        op.drop_table("organization_aliases")
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("knowledge_entries")}
    if "publication_revision" in columns:
        op.drop_column("knowledge_entries", "publication_revision")
