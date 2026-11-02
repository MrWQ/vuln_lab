"""Frozen initial schema snapshot; do not derive historical migrations from live ORM metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    op.create_table('ai_provider_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('base_url', sa.String(length=1000), nullable=False),
    sa.Column('model', sa.String(length=200), nullable=False),
    sa.Column('api_key_ciphertext', sa.Text(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('auto_publish', sa.Boolean(), nullable=False),
    sa.Column('capability_tested_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('daily_budget_usd', sa.Float(), nullable=False),
    sa.Column('input_price_per_million', sa.Float(), nullable=False),
    sa.Column('output_price_per_million', sa.Float(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('coverage_partitions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_key', sa.String(length=80), nullable=False),
    sa.Column('partition_key', sa.String(length=800), nullable=False),
    sa.Column('state', sa.String(length=24), nullable=False),
    sa.Column('cursor', sa.Text(), nullable=True),
    sa.Column('discovered_refs', sa.Integer(), nullable=False),
    sa.Column('processed_refs', sa.Integer(), nullable=False),
    sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_key', 'partition_key', name='uq_coverage_source_partition')
    )
    op.create_index(op.f('ix_coverage_partitions_source_key'), 'coverage_partitions', ['source_key'], unique=False)
    op.create_index(op.f('ix_coverage_partitions_state'), 'coverage_partitions', ['state'], unique=False)
    op.create_table('jobs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=64), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('state', sa.String(length=24), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('available_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('lease_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('lease_token', sa.String(length=64), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_jobs_kind'), 'jobs', ['kind'], unique=False)
    op.create_index(op.f('ix_jobs_lease_token'), 'jobs', ['lease_token'], unique=False)
    op.create_index(op.f('ix_jobs_state'), 'jobs', ['state'], unique=False)
    op.create_index('ix_jobs_state_created', 'jobs', ['state', 'created_at'], unique=False)
    op.create_table('knowledge_entries',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('vuln_type', sa.String(length=160), nullable=True),
    sa.Column('special_topic', sa.String(length=160), nullable=True),
    sa.Column('cve_id', sa.String(length=40), nullable=True),
    sa.Column('cwe_ids', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_reviewed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_knowledge_entries_cve_id'), 'knowledge_entries', ['cve_id'], unique=False)
    op.create_index(op.f('ix_knowledge_entries_special_topic'), 'knowledge_entries', ['special_topic'], unique=False)
    op.create_index(op.f('ix_knowledge_entries_status'), 'knowledge_entries', ['status'], unique=False)
    op.create_index(op.f('ix_knowledge_entries_title'), 'knowledge_entries', ['title'], unique=False)
    op.create_index(op.f('ix_knowledge_entries_vuln_type'), 'knowledge_entries', ['vuln_type'], unique=False)
    op.create_table('organizations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=240), nullable=False),
    sa.Column('normalized_name', sa.String(length=240), nullable=False),
    sa.Column('aliases', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_name'), 'organizations', ['name'], unique=True)
    op.create_index(op.f('ix_organizations_normalized_name'), 'organizations', ['normalized_name'], unique=True)
    op.create_table('source_documents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_key', sa.String(length=80), nullable=False),
    sa.Column('external_id', sa.String(length=800), nullable=False),
    sa.Column('url', sa.String(length=2000), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('source_revision', sa.String(length=200), nullable=True),
    sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('raw_sha256', sa.String(length=64), nullable=True),
    sa.Column('raw_object_key', sa.String(length=500), nullable=True),
    sa.Column('metadata', sa.JSON(), nullable=False),
    sa.Column('is_public', sa.Boolean(), nullable=False),
    sa.Column('license_hint', sa.String(length=300), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_key', 'external_id', name='uq_source_external')
    )
    op.create_index(op.f('ix_source_documents_source_key'), 'source_documents', ['source_key'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=300), nullable=False),
    sa.Column('role', sa.String(length=24), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_table('products',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(length=300), nullable=False),
    sa.Column('normalized_name', sa.String(length=300), nullable=False),
    sa.Column('ecosystem', sa.String(length=80), nullable=True),
    sa.Column('openness', sa.String(length=24), nullable=False),
    sa.Column('external_ids', sa.JSON(), nullable=False),
    sa.Column('aliases', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_products_name'), 'products', ['name'], unique=False)
    op.create_index(op.f('ix_products_normalized_name'), 'products', ['normalized_name'], unique=False)
    op.create_index(op.f('ix_products_openness'), 'products', ['openness'], unique=False)
    op.create_index(op.f('ix_products_organization_id'), 'products', ['organization_id'], unique=False)
    op.create_table('sessions',
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('token_hash')
    )
    op.create_index(op.f('ix_sessions_expires_at'), 'sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('source_revisions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_document_id', sa.Integer(), nullable=False),
    sa.Column('revision_key', sa.String(length=240), nullable=False),
    sa.Column('source_revision', sa.String(length=200), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('object_key', sa.String(length=500), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('metadata', sa.JSON(), nullable=False),
    sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['source_document_id'], ['source_documents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_document_id', 'revision_key', 'sha256', name='uq_source_revision_hash')
    )
    op.create_index(op.f('ix_source_revisions_sha256'), 'source_revisions', ['sha256'], unique=False)
    op.create_index(op.f('ix_source_revisions_source_document_id'), 'source_revisions', ['source_document_id'], unique=False)
    op.create_table('material_variants',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('entry_id', sa.String(length=36), nullable=False),
    sa.Column('source_document_id', sa.Integer(), nullable=False),
    sa.Column('source_revision_id', sa.Integer(), nullable=True),
    sa.Column('material_kind', sa.String(length=24), nullable=False),
    sa.Column('language', sa.String(length=80), nullable=True),
    sa.Column('source_url', sa.String(length=2000), nullable=False),
    sa.Column('source_revision', sa.String(length=200), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('object_key', sa.String(length=500), nullable=False),
    sa.Column('review_status', sa.String(length=32), nullable=False),
    sa.Column('evidence_grade', sa.String(length=32), nullable=False),
    sa.Column('gates', sa.JSON(), nullable=False),
    sa.Column('license_hint', sa.String(length=300), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['entry_id'], ['knowledge_entries.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['source_document_id'], ['source_documents.id'], ),
    sa.ForeignKeyConstraint(['source_revision_id'], ['source_revisions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_material_variants_entry_id'), 'material_variants', ['entry_id'], unique=False)
    op.create_index(op.f('ix_material_variants_material_kind'), 'material_variants', ['material_kind'], unique=False)
    op.create_index(op.f('ix_material_variants_review_status'), 'material_variants', ['review_status'], unique=False)
    op.create_index(op.f('ix_material_variants_sha256'), 'material_variants', ['sha256'], unique=False)
    op.create_index(op.f('ix_material_variants_source_document_id'), 'material_variants', ['source_document_id'], unique=False)
    op.create_index(op.f('ix_material_variants_source_revision_id'), 'material_variants', ['source_revision_id'], unique=False)
    op.create_table('product_vulnerabilities',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('entry_id', sa.String(length=36), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('version_expression', sa.String(length=500), nullable=True),
    sa.Column('version_status', sa.String(length=32), nullable=False),
    sa.Column('impact', sa.Text(), nullable=False),
    sa.Column('match_confidence', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['entry_id'], ['knowledge_entries.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_id'], ['products.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('entry_id', 'product_id', name='uq_entry_product')
    )
    op.create_index(op.f('ix_product_vulnerabilities_entry_id'), 'product_vulnerabilities', ['entry_id'], unique=False)
    op.create_index(op.f('ix_product_vulnerabilities_product_id'), 'product_vulnerabilities', ['product_id'], unique=False)
    op.create_table('ai_reviews',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('material_id', sa.String(length=36), nullable=False),
    sa.Column('model', sa.String(length=200), nullable=False),
    sa.Column('rubric_version', sa.String(length=40), nullable=False),
    sa.Column('decision', sa.String(length=32), nullable=False),
    sa.Column('gates', sa.JSON(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('estimated_cost_usd', sa.Float(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['material_id'], ['material_variants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_reviews_decision'), 'ai_reviews', ['decision'], unique=False)
    op.create_index(op.f('ix_ai_reviews_material_id'), 'ai_reviews', ['material_id'], unique=False)
    op.create_table('reproduction_packages',
    sa.Column('material_id', sa.String(length=36), nullable=False),
    sa.Column('prerequisites', sa.Text(), nullable=False),
    sa.Column('instructions', sa.Text(), nullable=False),
    sa.Column('success_criteria', sa.Text(), nullable=False),
    sa.Column('tested_versions', sa.String(length=500), nullable=True),
    sa.Column('execution_recorded', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['material_id'], ['material_variants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('material_id')
    )
    # PostgreSQL-only trigram indexes supplement portable B-tree indexes.
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_title_trgm ON knowledge_entries USING gin (title gin_trgm_ops)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_summary_trgm ON knowledge_entries USING gin (summary gin_trgm_ops)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_products_name_trgm ON products USING gin (name gin_trgm_ops)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_products_normalized_name_trgm ON products USING gin (normalized_name gin_trgm_ops)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_organizations_name_trgm ON organizations USING gin (name gin_trgm_ops)")


def downgrade():
    op.drop_table('reproduction_packages')
    op.drop_index(op.f('ix_ai_reviews_material_id'), table_name='ai_reviews')
    op.drop_index(op.f('ix_ai_reviews_decision'), table_name='ai_reviews')
    op.drop_table('ai_reviews')
    op.drop_index(op.f('ix_product_vulnerabilities_product_id'), table_name='product_vulnerabilities')
    op.drop_index(op.f('ix_product_vulnerabilities_entry_id'), table_name='product_vulnerabilities')
    op.drop_table('product_vulnerabilities')
    op.drop_index(op.f('ix_material_variants_source_revision_id'), table_name='material_variants')
    op.drop_index(op.f('ix_material_variants_source_document_id'), table_name='material_variants')
    op.drop_index(op.f('ix_material_variants_sha256'), table_name='material_variants')
    op.drop_index(op.f('ix_material_variants_review_status'), table_name='material_variants')
    op.drop_index(op.f('ix_material_variants_material_kind'), table_name='material_variants')
    op.drop_index(op.f('ix_material_variants_entry_id'), table_name='material_variants')
    op.drop_table('material_variants')
    op.drop_index(op.f('ix_source_revisions_source_document_id'), table_name='source_revisions')
    op.drop_index(op.f('ix_source_revisions_sha256'), table_name='source_revisions')
    op.drop_table('source_revisions')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_expires_at'), table_name='sessions')
    op.drop_table('sessions')
    op.drop_index(op.f('ix_products_organization_id'), table_name='products')
    op.drop_index(op.f('ix_products_openness'), table_name='products')
    op.drop_index(op.f('ix_products_normalized_name'), table_name='products')
    op.drop_index(op.f('ix_products_name'), table_name='products')
    op.drop_table('products')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_source_documents_source_key'), table_name='source_documents')
    op.drop_table('source_documents')
    op.drop_index(op.f('ix_organizations_normalized_name'), table_name='organizations')
    op.drop_index(op.f('ix_organizations_name'), table_name='organizations')
    op.drop_table('organizations')
    op.drop_index(op.f('ix_knowledge_entries_vuln_type'), table_name='knowledge_entries')
    op.drop_index(op.f('ix_knowledge_entries_title'), table_name='knowledge_entries')
    op.drop_index(op.f('ix_knowledge_entries_status'), table_name='knowledge_entries')
    op.drop_index(op.f('ix_knowledge_entries_special_topic'), table_name='knowledge_entries')
    op.drop_index(op.f('ix_knowledge_entries_cve_id'), table_name='knowledge_entries')
    op.drop_table('knowledge_entries')
    op.drop_index('ix_jobs_state_created', table_name='jobs')
    op.drop_index(op.f('ix_jobs_state'), table_name='jobs')
    op.drop_index(op.f('ix_jobs_lease_token'), table_name='jobs')
    op.drop_index(op.f('ix_jobs_kind'), table_name='jobs')
    op.drop_table('jobs')
    op.drop_index(op.f('ix_coverage_partitions_state'), table_name='coverage_partitions')
    op.drop_index(op.f('ix_coverage_partitions_source_key'), table_name='coverage_partitions')
    op.drop_table('coverage_partitions')
    op.drop_table('ai_provider_config')
    # ### end Alembic commands ###
