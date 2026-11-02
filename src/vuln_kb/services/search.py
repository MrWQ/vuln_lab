from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from datetime import datetime

from sqlalchemy import String, and_, exists, func, or_, select, tuple_
from sqlalchemy.orm import Session, joinedload

from vuln_kb.config import settings
from vuln_kb.models import (KnowledgeEntry, MaterialVariant, Organization, OrganizationAlias,
                            Product, ProductAlias, ProductIdentifier, ProductMaterialApplicability,
                            ProductVulnerability)
from vuln_kb.services.versions import match_version


def _filter_fingerprint(query: str, company: str, product: str, version: str, product_id: int | None) -> str:
    canonical = [" ".join(value.casefold().split()) for value in (query, company, product, version)] + [product_id]
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _sign(value: str) -> str:
    signature = hmac.new(settings.secret_key.encode(), value.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def _encode_cursor(entry: KnowledgeEntry, fingerprint: str) -> str:
    payload = {"v": 1, "f": fingerprint, "published_at": entry.published_at.isoformat() if entry.published_at else None,
               "title": entry.title, "id": entry.id}
    body = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{body}.{_sign(body)}"


def _decode_cursor(token: str, fingerprint: str) -> tuple[datetime | None, str, str]:
    try:
        body, signature = token.split(".", 1)
        if not hmac.compare_digest(signature, _sign(body)):
            raise ValueError
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError
        if payload.get("v") != 1 or payload.get("f") != fingerprint:
            raise ValueError
        published_at = datetime.fromisoformat(payload["published_at"]) if payload.get("published_at") else None
        title, entry_id = payload["title"], payload["id"]
        if not isinstance(title, str) or not isinstance(entry_id, str):
            raise ValueError
        return published_at, title, entry_id
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error) as exc:
        raise ValueError("分页游标无效，或与当前筛选条件不匹配") from exc


def search_entries(db: Session, query: str = "", company: str = "", product: str = "", version: str = "",
                   limit: int = 50, cursor: str | None = None, product_id: int | None = None
                   ) -> tuple[list[tuple[KnowledgeEntry, list[ProductVulnerability]]], int, str | None]:
    """Search published vulnerability records with stable, signed keyset pagination."""
    query, company, product, version = (value.strip() for value in (query, company, product, version))
    fingerprint = _filter_fingerprint(query, company, product, version, product_id)

    conditions = [KnowledgeEntry.id == ProductVulnerability.entry_id]
    if query:
        needle = f"%{query}%"
        conditions.append(or_(
            KnowledgeEntry.title.ilike(needle), KnowledgeEntry.summary.ilike(needle), KnowledgeEntry.cve_id.ilike(needle),
            Product.name.ilike(needle), Product.normalized_name.ilike(needle), Product.aliases.cast(String).ilike(needle),
            exists(select(1).where(ProductAlias.product_id == Product.id, ProductAlias.alias.ilike(needle))),
            exists(select(1).where(ProductIdentifier.product_id == Product.id, ProductIdentifier.value.ilike(needle))),
        ))
    if product:
        needle = f"%{product}%"
        conditions.append(or_(Product.name.ilike(needle), Product.normalized_name.ilike(needle),
                              Product.aliases.cast(String).ilike(needle),
                              exists(select(1).where(ProductAlias.product_id == Product.id,
                                                     ProductAlias.alias.ilike(needle))),
                              exists(select(1).where(ProductIdentifier.product_id == Product.id,
                                                     ProductIdentifier.value.ilike(needle)))) )
    if product_id is not None:
        conditions.append(Product.id == product_id)
    if company:
        company_pattern = f"%{company}%"
        conditions.append(or_(Product.organization.has(Organization.name.ilike(company_pattern)),
                              Product.organization.has(exists(select(1).where(
                                  OrganizationAlias.organization_id == Organization.id,
                                  OrganizationAlias.alias.ilike(company_pattern))))))
    material_applies = exists(select(1).select_from(ProductMaterialApplicability).join(
        MaterialVariant, MaterialVariant.id == ProductMaterialApplicability.material_id
    ).where(ProductMaterialApplicability.product_id == ProductVulnerability.product_id,
            MaterialVariant.entry_id == ProductVulnerability.entry_id,
            MaterialVariant.review_status == "approved"))
    conditions.append(material_applies)
    version_pairs: set[tuple[str, int]] | None = None
    if version:
        candidate_links = db.execute(select(ProductVulnerability.entry_id, ProductVulnerability.product_id,
                                            Product.ecosystem, ProductVulnerability.version_expression,
                                            ProductMaterialApplicability.version_expression,
                                            ProductVulnerability.version_status)
                                     .join(Product, Product.id == ProductVulnerability.product_id)
                                     .join(ProductMaterialApplicability,
                                           ProductMaterialApplicability.product_id == ProductVulnerability.product_id)
                                     .join(MaterialVariant, and_(
                                         MaterialVariant.id == ProductMaterialApplicability.material_id,
                                         MaterialVariant.entry_id == ProductVulnerability.entry_id,
                                         MaterialVariant.review_status == "approved"))
                                     .join(KnowledgeEntry, KnowledgeEntry.id == ProductVulnerability.entry_id)
                                     .where(*conditions)).all()
        version_pairs = set()
        for entry_id, product_id_value, ecosystem, vuln_expression, material_expression, _stored_status in candidate_links:
            vuln_status = match_version(ecosystem, version, vuln_expression)
            material_status = match_version(ecosystem, version, material_expression)
            # Unsupported/ecosystem-unknown cases stay visible and explicitly unknown.
            if vuln_status != "not_affected" and material_status != "not_affected":
                version_pairs.add((entry_id, product_id_value))
        if not version_pairs:
            return [], 0, None
    matching_links = select(ProductVulnerability.entry_id).join(
        Product, Product.id == ProductVulnerability.product_id
    ).join(KnowledgeEntry, KnowledgeEntry.id == ProductVulnerability.entry_id).where(*conditions)
    if version_pairs is not None:
        matching_links = matching_links.where(tuple_(ProductVulnerability.entry_id,
                                                       ProductVulnerability.product_id).in_(version_pairs))
    matching_ids = matching_links.distinct().subquery()
    base = select(KnowledgeEntry).where(KnowledgeEntry.status == "published",
                                         KnowledgeEntry.id.in_(select(matching_ids.c.entry_id)))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0

    if cursor:
        cursor_time, cursor_title, cursor_id = _decode_cursor(cursor, fingerprint)
        title_after = or_(KnowledgeEntry.title > cursor_title,
                          and_(KnowledgeEntry.title == cursor_title, KnowledgeEntry.id > cursor_id))
        if cursor_time is None:
            base = base.where(KnowledgeEntry.published_at.is_(None), title_after)
        else:
            base = base.where(or_(KnowledgeEntry.published_at < cursor_time,
                                  KnowledgeEntry.published_at.is_(None),
                                  and_(KnowledgeEntry.published_at == cursor_time, title_after)))

    entry_page = db.scalars(base.options(joinedload(KnowledgeEntry.products))
                            .order_by(KnowledgeEntry.published_at.desc().nullslast(),
                                      KnowledgeEntry.title.asc(), KnowledgeEntry.id.asc())
                            .limit(max(1, min(limit, 100)) + 1)).unique().all()
    has_more = len(entry_page) > max(1, min(limit, 100))
    entries = entry_page[:max(1, min(limit, 100))]
    if not entries:
        return [], total, None

    ids = [entry.id for entry in entries]
    relation_stmt = (select(ProductVulnerability).join(Product, Product.id == ProductVulnerability.product_id)
                     .join(KnowledgeEntry, KnowledgeEntry.id == ProductVulnerability.entry_id)
                     .where(ProductVulnerability.entry_id.in_(ids), *conditions)
                     .options(joinedload(ProductVulnerability.product).joinedload(Product.organization)))
    if version:
        relation_stmt = relation_stmt.where(tuple_(ProductVulnerability.entry_id,
                                                     ProductVulnerability.product_id).in_(version_pairs or set()))
    relation_stmt = relation_stmt.where(exists(select(1).select_from(ProductMaterialApplicability).join(
        MaterialVariant, MaterialVariant.id == ProductMaterialApplicability.material_id
    ).where(ProductMaterialApplicability.product_id == ProductVulnerability.product_id,
            MaterialVariant.entry_id == ProductVulnerability.entry_id,
            MaterialVariant.review_status == "approved")))
    links_by_entry: dict[str, list[ProductVulnerability]] = {}
    for relation in db.scalars(relation_stmt).unique().all():
        links_by_entry.setdefault(relation.entry_id, []).append(relation)

    next_cursor = _encode_cursor(entries[-1], fingerprint) if has_more else None
    return [(entry, links_by_entry.get(entry.id, [])) for entry in entries], total, next_cursor
