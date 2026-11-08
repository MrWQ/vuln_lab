from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vuln_kb.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    normalized_name: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)


class OrganizationAlias(Base):
    __tablename__ = "organization_aliases"
    __table_args__ = (UniqueConstraint("organization_id", "normalized_alias", name="uq_organization_alias_normalized"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(240))
    normalized_alias: Mapped[str] = mapped_column(String(240), index=True)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    organization: Mapped[Organization] = relationship()


class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    normalized_name: Mapped[str] = mapped_column(String(300), index=True)
    ecosystem: Mapped[str | None] = mapped_column(String(80))
    openness: Mapped[str] = mapped_column(String(24), default="unknown", index=True)
    external_ids: Mapped[list] = mapped_column(JSON, default=list)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    organization: Mapped[Organization | None] = relationship()
    alias_rows: Mapped[list["ProductAlias"]] = relationship(back_populates="product", cascade="all, delete-orphan")


class ProductAlias(Base):
    __tablename__ = "product_aliases"
    __table_args__ = (UniqueConstraint("product_id", "normalized_alias", name="uq_product_alias_normalized"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(300))
    normalized_alias: Mapped[str] = mapped_column(String(300), index=True)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    product: Mapped[Product] = relationship(back_populates="alias_rows")


class ProductIdentifier(Base):
    __tablename__ = "product_identifiers"
    __table_args__ = (UniqueConstraint("namespace", "value", name="uq_product_identifier"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True)
    namespace: Mapped[str] = mapped_column(String(120))
    value: Mapped[str] = mapped_column(String(500))
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    product: Mapped[Product] = relationship()


class KnowledgeEntry(Base):
    __tablename__ = "knowledge_entries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(500), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    vuln_type: Mapped[str | None] = mapped_column(String(160), index=True)
    special_topic: Mapped[str | None] = mapped_column(String(160), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(40), index=True)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="candidate", index=True)
    publication_revision: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    products: Mapped[list["ProductVulnerability"]] = relationship(back_populates="entry", cascade="all, delete-orphan")
    materials: Mapped[list["MaterialVariant"]] = relationship(back_populates="entry", cascade="all, delete-orphan")


class ProductVulnerability(Base):
    __tablename__ = "product_vulnerabilities"
    __table_args__ = (UniqueConstraint("entry_id", "product_id", name="uq_entry_product"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    entry_id: Mapped[str] = mapped_column(ForeignKey("knowledge_entries.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    version_expression: Mapped[str | None] = mapped_column(String(500))
    version_status: Mapped[str] = mapped_column(String(32), default="unknown")
    impact: Mapped[str] = mapped_column(Text, default="")
    match_confidence: Mapped[float] = mapped_column(Float, default=0.5)
    entry: Mapped[KnowledgeEntry] = relationship(back_populates="products")
    product: Mapped[Product] = relationship()


class SourceDocument(Base):
    __tablename__ = "source_documents"
    __table_args__ = (UniqueConstraint("source_key", "external_id", name="uq_source_external"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_key: Mapped[str] = mapped_column(String(80), index=True)
    external_id: Mapped[str] = mapped_column(String(800))
    url: Mapped[str] = mapped_column(String(2000))
    title: Mapped[str] = mapped_column(String(500), default="")
    source_revision: Mapped[str | None] = mapped_column(String(200))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_sha256: Mapped[str | None] = mapped_column(String(64))
    raw_object_key: Mapped[str | None] = mapped_column(String(500))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True)
    license_hint: Mapped[str | None] = mapped_column(String(300))


class SourceRevision(Base):
    __tablename__ = "source_revisions"
    __table_args__ = (UniqueConstraint("source_document_id", "revision_key", "sha256", name="uq_source_revision_hash"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_document_id: Mapped[int] = mapped_column(ForeignKey("source_documents.id", ondelete="CASCADE"), index=True)
    revision_key: Mapped[str] = mapped_column(String(240))
    source_revision: Mapped[str | None] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(500))
    size_bytes: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MaterialVariant(Base):
    __tablename__ = "material_variants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entry_id: Mapped[str] = mapped_column(ForeignKey("knowledge_entries.id", ondelete="CASCADE"), index=True)
    source_document_id: Mapped[int] = mapped_column(ForeignKey("source_documents.id"), index=True)
    source_revision_id: Mapped[int | None] = mapped_column(ForeignKey("source_revisions.id"), index=True)
    material_kind: Mapped[str] = mapped_column(String(24), index=True)
    language: Mapped[str | None] = mapped_column(String(80))
    source_url: Mapped[str] = mapped_column(String(2000))
    source_revision: Mapped[str | None] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(500))
    review_status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    evidence_grade: Mapped[str] = mapped_column(String(32), default="unassessed")
    gates: Mapped[dict] = mapped_column(JSON, default=dict)
    license_hint: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    entry: Mapped[KnowledgeEntry] = relationship(back_populates="materials")
    source_document: Mapped[SourceDocument] = relationship()
    source_revision_record: Mapped[SourceRevision | None] = relationship()
    reproduction: Mapped["ReproductionPackage | None"] = relationship(back_populates="material", cascade="all, delete-orphan", uselist=False)
    product_applicabilities: Mapped[list["ProductMaterialApplicability"]] = relationship(
        back_populates="material", cascade="all, delete-orphan")


class ProductMaterialApplicability(Base):
    __tablename__ = "product_material_applicability"
    __table_args__ = (UniqueConstraint("material_id", "product_id", name="uq_material_product_applicability"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    material_id: Mapped[str] = mapped_column(ForeignKey("material_variants.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True)
    version_expression: Mapped[str | None] = mapped_column(String(500))
    version_status: Mapped[str] = mapped_column(String(32), default="unknown")
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    material: Mapped[MaterialVariant] = relationship(back_populates="product_applicabilities")
    product: Mapped[Product] = relationship()


class ObjectBlob(Base):
    """Immutable object inventory used for verified reads and orphan collection."""
    __tablename__ = "object_blobs"
    __table_args__ = (UniqueConstraint("namespace", "sha256", name="uq_object_namespace_sha256"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    namespace: Mapped[str] = mapped_column(String(24), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(500), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PublicationOutbox(Base):
    __tablename__ = "publication_outbox"
    __table_args__ = (UniqueConstraint("entry_id", "publication_revision", name="uq_publication_outbox_revision"),
                      Index("ix_publication_outbox_state_created", "state", "created_at"))
    id: Mapped[int] = mapped_column(primary_key=True)
    entry_id: Mapped[str] = mapped_column(ForeignKey("knowledge_entries.id", ondelete="CASCADE"), index=True)
    publication_revision: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReproductionPackage(Base):
    __tablename__ = "reproduction_packages"
    material_id: Mapped[str] = mapped_column(ForeignKey("material_variants.id", ondelete="CASCADE"), primary_key=True)
    prerequisites: Mapped[str] = mapped_column(Text, default="")
    instructions: Mapped[str] = mapped_column(Text, default="")
    success_criteria: Mapped[str] = mapped_column(Text, default="")
    tested_versions: Mapped[str | None] = mapped_column(String(500))
    execution_recorded: Mapped[bool] = mapped_column(Boolean, default=False)
    material: Mapped[MaterialVariant] = relationship(back_populates="reproduction")


class AIReview(Base):
    __tablename__ = "ai_reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    material_id: Mapped[str] = mapped_column(ForeignKey("material_variants.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("ai_review_tasks.id", ondelete="SET NULL"), index=True)
    model: Mapped[str] = mapped_column(String(200))
    rubric_version: Mapped[str] = mapped_column(String(40), default="admission-1.2")
    decision: Mapped[str] = mapped_column(String(32), index=True)
    gates: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_state_created", "state", "created_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(64), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CoveragePartition(Base):
    __tablename__ = "coverage_partitions"
    __table_args__ = (UniqueConstraint("source_key", "partition_key", name="uq_coverage_source_partition"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_key: Mapped[str] = mapped_column(String(80), index=True)
    partition_key: Mapped[str] = mapped_column(String(800))
    state: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    cursor: Mapped[str | None] = mapped_column(Text)
    discovered_refs: Mapped[int] = mapped_column(Integer, default=0)
    processed_refs: Mapped[int] = mapped_column(Integer, default=0)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(24), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AIProviderConfig(Base):
    __tablename__ = "ai_provider_config"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    base_url: Mapped[str] = mapped_column(String(1000))
    model: Mapped[str] = mapped_column(String(200))
    api_key_ciphertext: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_publish: Mapped[bool] = mapped_column(Boolean, default=True)
    capability_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    configuration_revision: Mapped[int] = mapped_column(Integer, default=1)
    capability_report: Mapped[dict] = mapped_column(JSON, default=dict)
    daily_budget_usd: Mapped[float] = mapped_column(Float, default=5.0)
    input_price_per_million: Mapped[float] = mapped_column(Float, default=0.0)
    output_price_per_million: Mapped[float] = mapped_column(Float, default=0.0)
    requests_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    max_concurrent_reviews: Mapped[int] = mapped_column(Integer, default=2)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AIReviewTask(Base):
    __tablename__ = "ai_review_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    material_id: Mapped[str] = mapped_column(ForeignKey("material_variants.id", ondelete="CASCADE"), index=True)
    provider_id: Mapped[int | None] = mapped_column(ForeignKey("ai_provider_config.id", ondelete="SET NULL"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), unique=True)
    input_sha256: Mapped[str] = mapped_column(String(64))
    provider_revision: Mapped[int] = mapped_column(Integer)
    rubric_version: Mapped[str] = mapped_column(String(80))
    prompt_version: Mapped[str] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    reserved_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    actual_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AIUsageRecord(Base):
    __tablename__ = "ai_usage_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("ai_review_tasks.id", ondelete="CASCADE"), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    provider_revision: Mapped[int] = mapped_column(Integer)
    model: Mapped[str] = mapped_column(String(200))
    state: Mapped[str] = mapped_column(String(24), default="reserved", index=True)
    reserved_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    actual_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    error_category: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("task_id", "attempt", name="uq_ai_usage_task_attempt"),)

