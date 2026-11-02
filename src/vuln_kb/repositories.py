"""Idempotent persistence primitives for canonical domain entities."""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_kb.models import (
    KnowledgeEntry, MaterialVariant, Organization, OrganizationAlias, Product,
    ProductAlias, ProductIdentifier, ProductMaterialApplicability,
    ProductVulnerability, SourceDocument, SourceRevision,
)


def normalize_identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")


def upsert_source(db: Session, *, source_key: str, external_id: str, url: str, title: str = "",
                  revision: str | None = None, sha256: str | None = None, object_key: str | None = None,
                  size_bytes: int | None = None, metadata: dict | None = None,
                  license_hint: str | None = None, is_public: bool = True) -> tuple[SourceDocument, SourceRevision | None, bool]:
    source = db.scalar(select(SourceDocument).where(SourceDocument.source_key == source_key,
                                                     SourceDocument.external_id == external_id))
    created = source is None
    if source is None:
        source = SourceDocument(source_key=source_key, external_id=external_id, url=url, title=title)
        db.add(source)
        db.flush()
    source.url, source.title = url, title
    source.source_revision, source.raw_sha256, source.raw_object_key = revision, sha256, object_key
    source.metadata_json, source.license_hint, source.is_public = metadata or {}, license_hint, is_public
    db.flush()
    revision_row = None
    if sha256 and object_key:
        revision_key = revision or sha256
        revision_row = db.scalar(select(SourceRevision).where(
            SourceRevision.source_document_id == source.id,
            SourceRevision.revision_key == revision_key,
            SourceRevision.sha256 == sha256,
        ))
        if revision_row is None:
            revision_row = SourceRevision(source_document_id=source.id, revision_key=revision_key,
                                          source_revision=revision, sha256=sha256, object_key=object_key,
                                          size_bytes=size_bytes or 0, metadata_json=metadata or {})
            db.add(revision_row)
            db.flush()
    return source, revision_row, created


def get_or_create_organization(db: Session, name: str, aliases: list[str] | None = None,
                               evidence: dict | None = None) -> tuple[Organization, bool]:
    normalized = normalize_identity(name) or "unknown"
    row = db.scalar(select(Organization).where(Organization.normalized_name == normalized))
    created = row is None
    if row is None:
        row = Organization(name=name.strip()[:240], normalized_name=normalized, aliases=[])
        db.add(row)
        db.flush()
    for alias in aliases or []:
        normalized_alias = normalize_identity(alias)
        if normalized_alias and normalized_alias != normalized:
            existing = db.scalar(select(OrganizationAlias).where(
                OrganizationAlias.organization_id == row.id,
                OrganizationAlias.normalized_alias == normalized_alias))
            if existing is None:
                db.add(OrganizationAlias(organization_id=row.id, alias=alias.strip()[:240],
                                         normalized_alias=normalized_alias, evidence_json=evidence or {}))
    db.flush()
    return row, created


def get_or_create_product(db: Session, name: str, *, organization_id: int | None = None,
                          ecosystem: str | None = None, openness: str = "unknown",
                          aliases: list[str] | None = None, identifiers: dict[str, str] | None = None,
                          evidence: dict | None = None) -> tuple[Product, bool]:
    normalized = normalize_identity(name) or name.strip().casefold()
    statement = select(Product).where(Product.normalized_name == normalized,
                                       Product.organization_id == organization_id)
    row = db.scalar(statement)
    created = row is None
    if row is None:
        row = Product(organization_id=organization_id, name=name.strip()[:300], normalized_name=normalized,
                      ecosystem=ecosystem, openness=openness, aliases=[], external_ids=[])
        db.add(row)
        db.flush()
    elif ecosystem and not row.ecosystem:
        row.ecosystem = ecosystem
    for alias in aliases or []:
        normalized_alias = normalize_identity(alias)
        if normalized_alias and normalized_alias != normalized:
            existing = db.scalar(select(ProductAlias).where(
                ProductAlias.product_id == row.id,
                ProductAlias.normalized_alias == normalized_alias))
            if existing is None:
                db.add(ProductAlias(product_id=row.id, alias=alias.strip()[:300],
                                    normalized_alias=normalized_alias, evidence_json=evidence or {}))
    for namespace, value in (identifiers or {}).items():
        if not namespace.strip() or not value.strip():
            continue
        existing = db.scalar(select(ProductIdentifier).where(
            ProductIdentifier.namespace == namespace.strip().casefold(),
            ProductIdentifier.value == value.strip()))
        if existing is None:
            db.add(ProductIdentifier(product_id=row.id, namespace=namespace.strip().casefold(),
                                     value=value.strip()[:500], evidence_json=evidence or {}))
        elif existing.product_id != row.id:
            raise ValueError(f"product identifier conflicts with another product: {namespace}:{value}")
    db.flush()
    return row, created


def upsert_product_vulnerability(db: Session, entry: KnowledgeEntry, product: Product, *,
                                 version_expression: str | None = None, version_status: str = "unknown",
                                 impact: str = "", confidence: float = 0.5) -> tuple[ProductVulnerability, bool]:
    relation = db.scalar(select(ProductVulnerability).where(
        ProductVulnerability.entry_id == entry.id, ProductVulnerability.product_id == product.id))
    created = relation is None
    if relation is None:
        relation = ProductVulnerability(entry_id=entry.id, product_id=product.id)
        db.add(relation)
    relation.version_expression = version_expression
    relation.version_status = version_status
    relation.impact = impact
    relation.match_confidence = max(0.0, min(1.0, float(confidence)))
    db.flush()
    return relation, created


def link_material_to_product(db: Session, material: MaterialVariant, product: Product, *,
                             version_expression: str | None = None, version_status: str = "unknown",
                             evidence_refs: list[str] | None = None) -> tuple[ProductMaterialApplicability, bool]:
    link = db.scalar(select(ProductMaterialApplicability).where(
        ProductMaterialApplicability.material_id == material.id,
        ProductMaterialApplicability.product_id == product.id))
    created = link is None
    if link is None:
        link = ProductMaterialApplicability(material_id=material.id, product_id=product.id)
        db.add(link)
    link.version_expression = version_expression
    link.version_status = version_status
    link.evidence_refs = evidence_refs or []
    db.flush()
    return link, created
