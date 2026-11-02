"""Single publication qualification boundary and transactional outbox writer."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from vuln_kb.domain.contracts import MaterialReviewState, PublicationState
from vuln_kb.domain.states import can_transition
from vuln_kb.models import (
    KnowledgeEntry, MaterialVariant, ProductMaterialApplicability,
    ProductVulnerability, PublicationOutbox, ReproductionPackage,
)
from vuln_kb.storage import ObjectStore

GATE_KEYS = ("G1_source", "G2_material", "G3_prerequisites", "G4_success_impact", "G5_usable")


class PublicationError(ValueError):
    pass


def _approved_materials(db: Session, entry_id: str) -> list[MaterialVariant]:
    return db.scalars(select(MaterialVariant).where(
        MaterialVariant.entry_id == entry_id,
        MaterialVariant.review_status == MaterialReviewState.APPROVED.value,
    ).options(joinedload(MaterialVariant.reproduction))).unique().all()


def _qualified_material(db: Session, material: MaterialVariant, store: ObjectStore) -> bool:
    package = material.reproduction
    if package is None or not all((package.prerequisites.strip(), package.instructions.strip(), package.success_criteria.strip())):
        return False
    gates = material.gates if isinstance(material.gates, dict) else {}
    if any(gates.get(key) != "pass" for key in GATE_KEYS):
        return False
    failures = gates.get("server_failures") or []
    if failures:
        return False
    try:
        content = store.read(material.object_key)
    except (OSError, ValueError):
        return False
    return bool(content) and hashlib.sha256(content).hexdigest() == material.sha256


def _outbox_payload(db: Session, entry: KnowledgeEntry, materials: list[MaterialVariant]) -> dict:
    products = db.scalars(select(ProductVulnerability).where(ProductVulnerability.entry_id == entry.id)
                          .order_by(ProductVulnerability.product_id)).all()
    product_rows = [{"product_id": row.product_id, "version_expression": row.version_expression,
                     "version_status": row.version_status} for row in products]
    material_rows = []
    for material in sorted(materials, key=lambda item: item.id):
        applicability = db.scalars(select(ProductMaterialApplicability).where(
            ProductMaterialApplicability.material_id == material.id)
            .order_by(ProductMaterialApplicability.product_id)).all()
        material_rows.append({"material_id": material.id, "sha256": material.sha256,
                              "object_key": material.object_key,
                              "product_ids": [link.product_id for link in applicability]})
    data = {"entry_id": entry.id, "title": entry.title, "summary": entry.summary,
            "cve_id": entry.cve_id, "products": product_rows, "materials": material_rows}
    fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False,
                                              separators=(",", ":")).encode()).hexdigest()
    return {"snapshot": data, "snapshot_sha256": fingerprint}


def _emit(db: Session, entry: KnowledgeEntry, event_type: str, payload: dict) -> PublicationOutbox | None:
    latest = db.scalar(select(PublicationOutbox).where(PublicationOutbox.entry_id == entry.id)
                       .order_by(PublicationOutbox.publication_revision.desc()).limit(1))
    fingerprint = payload.get("snapshot_sha256")
    if latest and latest.payload.get("snapshot_sha256") == fingerprint and latest.event_type == event_type:
        return None
    revision = latest.publication_revision + 1 if latest else max(1, entry.publication_revision)
    entry.publication_revision = revision
    event = PublicationOutbox(entry_id=entry.id, publication_revision=revision,
                              event_type=event_type, payload=payload, state="queued")
    db.add(event)
    db.flush()
    return event


def publish_entry(db: Session, entry: KnowledgeEntry, store: ObjectStore | None = None) -> PublicationOutbox:
    """Set publication state and outbox event in the caller's single DB transaction."""
    store = store or ObjectStore()
    materials = _approved_materials(db, entry.id)
    qualified = [material for material in materials if _qualified_material(db, material, store)]
    if not qualified:
        raise PublicationError("no qualified approved material with intact object, gates, and reproduction package")
    product_links = db.scalars(select(ProductVulnerability).where(ProductVulnerability.entry_id == entry.id)).all()
    if not product_links:
        raise PublicationError("case has no product applicability relation")
    applicable_products = set(db.scalars(select(ProductMaterialApplicability.product_id).join(
        MaterialVariant, MaterialVariant.id == ProductMaterialApplicability.material_id).where(
            MaterialVariant.entry_id == entry.id,
            MaterialVariant.review_status == MaterialReviewState.APPROVED.value,
    )).all())
    if not applicable_products:
        raise PublicationError("approved material has no product-level applicability")
    allowed = entry.status == "candidate" or (
        entry.status in {state.value for state in PublicationState}
        and can_transition(PublicationState(entry.status), PublicationState.PUBLISHED)
    )
    if not allowed and entry.status != PublicationState.PUBLISHED.value:
        raise PublicationError(f"entry cannot transition to published from {entry.status}")
    for material in qualified:
        material.gates = {**(material.gates or {}), "G6_review_complete": "pass",
                          "g6_computed_by": "publication-service"}
    if entry.status == PublicationState.PUBLISHED.value:
        # A second publish is idempotent if the published snapshot is unchanged.
        payload = _outbox_payload(db, entry, qualified)
        event = _emit(db, entry, "published", payload)
        if event is None:
            db.flush()
            return db.scalar(select(PublicationOutbox).where(PublicationOutbox.entry_id == entry.id)
                             .order_by(PublicationOutbox.publication_revision.desc()).limit(1))
    else:
        entry.status = PublicationState.PUBLISHED.value
        entry.published_at = datetime.now(timezone.utc)
        payload = _outbox_payload(db, entry, qualified)
        event = _emit(db, entry, "published", payload)
    db.flush()
    return event


def withdraw_entry(db: Session, entry: KnowledgeEntry, reason: str) -> PublicationOutbox:
    if entry.status not in {PublicationState.PUBLISHED.value, PublicationState.NEEDS_REVALIDATION.value}:
        raise PublicationError("only published or revalidation-required entries can be withdrawn")
    entry.status = PublicationState.WITHDRAWN.value
    payload = {"entry_id": entry.id, "reason": reason[:1200], "snapshot_sha256": None}
    event = _emit(db, entry, "withdrawn", payload)
    db.flush()
    return event


def revoke_material(db: Session, material: MaterialVariant, reason: str) -> bool:
    """Revoke one implementation and remove product search eligibility when no alternative remains."""
    entry = db.get(KnowledgeEntry, material.entry_id)
    if entry is None:
        raise PublicationError("material has no vulnerability entry")
    material.review_status = MaterialReviewState.REJECTED.value
    material.gates = {**(material.gates or {}), "revocation_reason": reason[:1200]}
    survivors = [candidate for candidate in _approved_materials(db, entry.id) if candidate.id != material.id]
    if not survivors:
        if entry.status == PublicationState.PUBLISHED.value:
            entry.status = PublicationState.NEEDS_REVALIDATION.value
        payload = {"entry_id": entry.id, "reason": reason[:1200], "snapshot_sha256": None}
        _emit(db, entry, "material_revoked", payload)
        db.flush()
        return False
    payload = _outbox_payload(db, entry, survivors)
    _emit(db, entry, "material_set_updated", payload)
    db.flush()
    return True
