from __future__ import annotations

import math
import hashlib
import re
import uuid
from datetime import datetime, time, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_kb.ai_review import _provider, review_material, verify_claim_evidence
from vuln_kb.adapters.contracts import RawSnapshot
from vuln_kb.models import (AIReview, AIReviewTask, KnowledgeEntry, MaterialVariant, Organization, Product,
                            Job, ProductVulnerability, ReproductionPackage, SourceDocument, SourceRevision, utcnow)
from vuln_kb.repositories import get_or_create_organization, get_or_create_product, link_material_to_product
from vuln_kb.services.publication import publish_entry, revoke_material
from vuln_kb.storage import ObjectStore, register_object


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _gate_passed(result: dict, text: str, snapshot: RawSnapshot, content_size: int,
                 source_sha256: str | None = None) -> tuple[bool, dict, list[str]]:
    failures: list[str] = []
    provenance_text = "\n".join([text, snapshot.ref.title, snapshot.ref.url,
                                  str(snapshot.ref.metadata.get("path") or ""),
                                  str(snapshot.ref.metadata.get("repo") or "")])
    gates = result.get("gates") if isinstance(result.get("gates"), dict) else {}
    required = ("G1_source", "G2_material", "G3_prerequisites", "G4_success_impact", "G5_usable")
    for name in required:
        if gates.get(name) != "pass":
            failures.append(f"{name} 未通过")
    source_sha256 = source_sha256 or hashlib.sha256(snapshot.content if isinstance(snapshot.content, bytes)
                                                    else text.encode("utf-8")).hexdigest()
    claim_grounding, citation_failures = verify_claim_evidence(result, text, source_sha256)
    failures.extend(citation_failures)
    if result.get("version_expression") and not claim_grounding.get("version"):
        failures.append("受影响版本缺少精确原文证据")
    allowed_hosts = set(snapshot.ref.metadata.get("allowed_hosts") or [])
    allowed_hosts.update({"github.com", "www.exploit-db.com"})
    source_host = (urlparse(snapshot.ref.url).hostname or "").lower()
    if urlparse(snapshot.ref.url).scheme != "https" or source_host not in allowed_hosts:
        failures.append("来源 URL 不在已知公共来源域名")
    if content_size == 0:
        failures.append("材料为空")
    if not result.get("title") or not result.get("summary"):
        failures.append("标题或摘要缺失")
    for field, minimum, label in (("prerequisites", 5, "前置条件"), ("instructions", 30, "复现步骤"),
                                  ("success_criteria", 8, "成功判据"), ("impact", 8, "影响说明")):
        value = result.get(field)
        if not isinstance(value, str) or len(value.strip()) < minimum:
            failures.append(f"{label}不完整")
    missing_items = result.get("missing_items") if isinstance(result.get("missing_items"), list) else []
    for item in missing_items:
        if isinstance(item, dict) and item.get("blocking") is True:
            failures.append(f"AI 标记存在阻塞缺项：{str(item.get('code') or 'unknown')[:120]}")
    company, product = result.get("company"), result.get("product")
    if not product:
        failures.append("产品无法识别")
    confidence = result.get("confidence", 0)
    if not isinstance(confidence, (int, float)) or not math.isfinite(float(confidence)) or not 0.75 <= confidence <= 1:
        failures.append("产品/漏洞判断置信度低于 0.75")
    return not failures, {"gates": gates, "claim_evidence": claim_grounding, "missing_items": missing_items,
                          "company": company, "product": product}, failures


async def import_snapshot(db: Session, snapshot: RawSnapshot, store: ObjectStore | None = None,
                          force_review: bool = False) -> dict:
    store = store or ObjectStore()
    if isinstance(snapshot.content, bytes):
        content_size = len(snapshot.content)
        digest, object_key = store.put(snapshot.content, namespace="candidate")
        content = snapshot.content
    else:
        digest, object_key, content_size = await store.put_async_chunks(snapshot.content, namespace="candidate")
        content = store.read(object_key)
    text = content.decode("utf-8", errors="replace")
    register_object(db, digest, object_key, content_size)
    source_metadata = dict(snapshot.ref.metadata)
    source_metadata.setdefault("original_filename", source_metadata.get("path") or snapshot.ref.title)
    source = db.scalar(select(SourceDocument).where(SourceDocument.source_key == snapshot.ref.source_key,
                                                    SourceDocument.external_id == snapshot.ref.external_id))
    if source is None:
        source = SourceDocument(source_key=snapshot.ref.source_key, external_id=snapshot.ref.external_id,
                                url=snapshot.ref.url, title=snapshot.ref.title, is_public=True)
        db.add(source)
        db.flush()
    source.url = snapshot.ref.url
    source.title = snapshot.ref.title
    source.source_revision = snapshot.revision
    source.raw_sha256 = digest
    source.raw_object_key = object_key
    source.metadata_json = source_metadata
    source.license_hint = snapshot.license_hint
    source.fetched_at = utcnow()

    revision_key = snapshot.revision or digest
    source_revision = db.scalar(select(SourceRevision).where(SourceRevision.source_document_id == source.id,
                                                               SourceRevision.revision_key == revision_key,
                                                               SourceRevision.sha256 == digest))
    if source_revision is None:
        source_revision = SourceRevision(source_document_id=source.id, revision_key=revision_key,
                                         source_revision=snapshot.revision, sha256=digest,
                                         object_key=object_key, size_bytes=content_size,
                                         metadata_json=source_metadata)
        db.add(source_revision)
        db.flush()

    existing = db.scalar(select(MaterialVariant).where(MaterialVariant.source_document_id == source.id,
                                                        MaterialVariant.sha256 == digest))
    if existing and not force_review:
        db.commit()
        return {"status": existing.review_status, "material_id": existing.id, "duplicate": True}
    if existing:
        material = existing
        entry = db.get(KnowledgeEntry, existing.entry_id)
    else:
        entry = KnowledgeEntry(id=str(uuid.uuid4()), title=snapshot.ref.title[:500], summary="", status="candidate")
        db.add(entry)
        db.flush()
        path_name = str(snapshot.ref.metadata.get("path") or snapshot.ref.title)
        suffix = path_name.rsplit(".", 1)[-1].lower() if "." in path_name.rsplit("/", 1)[-1] else ""
        code_suffixes = {"py", "rb", "php", "js", "ts", "go", "java", "sh", "pl", "c", "cpp", "ps1"}
        kind = ("exp" if snapshot.ref.source_key == "exploitdb" else
                "poc" if snapshot.ref.metadata.get("poc") or suffix in code_suffixes else "procedure")
        material = MaterialVariant(id=str(uuid.uuid4()), entry_id=entry.id, source_document_id=source.id,
                                   source_revision_id=source_revision.id,
                                   material_kind=kind, source_url=snapshot.ref.url, source_revision=snapshot.revision,
                                   sha256=digest, object_key=object_key, review_status="pending",
                                   license_hint=snapshot.license_hint)
        db.add(material)
        db.flush()
        # Persist the candidate before any remote model call so timeouts never lose provenance.
        db.commit()

    previous_review_status = material.review_status
    try:
        result, input_tokens, output_tokens, model_cost, review_task_id = await review_material(db, material, text, digest)
        proposed_kind = result.get("material_kind")
        if proposed_kind in {"poc", "exp", "procedure", "other"}:
            material.material_kind = proposed_kind
        material.language = str(result.get("language") or "")[:80] or None
        passed, evidence, failures = _gate_passed(result, text, snapshot, content_size, digest)
        provider_cfg, auto_publish = _provider(db)
        decision = result.get("decision", "needs_review")
        eligible = passed and decision == "eligible"
        cost = float(model_cost.split("cost=")[-1])
        review = db.scalar(select(AIReview).where(AIReview.task_id == review_task_id))
        if review is None:
            review = AIReview(material_id=material.id, model=provider_cfg.get("model", "configured"),
                              task_id=review_task_id,
                              decision="eligible" if eligible else "needs_review", gates=result.get("gates", {}),
                              evidence={**evidence, "failures": failures}, estimated_cost_usd=cost)
            db.add(review)
        material.gates = {**(result.get("gates") or {}), "server_failures": failures,
                          "input_tokens": input_tokens, "output_tokens": output_tokens}
        if eligible:
            material.review_status = "approved"
            material.evidence_grade = "material_reviewed"
        elif previous_review_status == "approved":
            revoke_material(db, material, "重新审核后材料未达到发布门槛")
            material.evidence_grade = "unassessed"
        else:
            material.review_status = "pending"
            material.evidence_grade = "unassessed"
        if eligible:
            approved_digest, approved_key, approved_size = store.promote(object_key)
            register_object(db, approved_digest, approved_key, approved_size)
            material.object_key = approved_key
        package = db.get(ReproductionPackage, material.id)
        if package is None:
            package = ReproductionPackage(material_id=material.id)
        package.prerequisites = str(result.get("prerequisites") or "")
        package.instructions = str(result.get("instructions") or "")
        package.success_criteria = str(result.get("success_criteria") or "")
        package.tested_versions = result.get("tested_versions")
        package.execution_recorded = False
        db.add(package)
        if eligible and result.get("product"):
            org_name = (str(result.get("company") or "未知厂商")).strip()[:240]
            org, _ = get_or_create_organization(db, org_name)
            product_name = str(result["product"]).strip()[:300]
            product, _ = get_or_create_product(db, product_name, organization_id=org.id,
                                               aliases=result.get("product_aliases") or [],
                                               evidence={"source_url": snapshot.ref.url,
                                                         "source_revision": snapshot.revision,
                                                         "sha256": digest})
            if result.get("cve_id"):
                canonical = db.scalar(select(KnowledgeEntry).join(ProductVulnerability).where(
                    KnowledgeEntry.cve_id == result.get("cve_id"), ProductVulnerability.product_id == product.id,
                    KnowledgeEntry.id != entry.id).limit(1))
                if canonical:
                    material.entry_id = canonical.id
                    db.flush()
                    db.delete(entry)
                    entry = canonical
            entry.title = str(result.get("title") or snapshot.ref.title)[:500]
            entry.summary = str(result.get("summary") or "")[:10000]
            entry.vuln_type = str(result.get("vuln_type") or "")[:160] or None
            special = re.search(r"(?i)\b(log[24]shell|php2shell)\b", entry.title)
            entry.special_topic = special.group(1).lower() if special else None
            entry.cve_id = result.get("cve_id")
            entry.cwe_ids = result.get("cwe_ids") or []
            already_published = entry.status == "published"
            entry.status = "published" if auto_publish or already_published else "candidate"
            if entry.status == "published" and entry.published_at is None:
                entry.published_at = utcnow()
            entry.last_reviewed_at = utcnow()
            relation = db.scalar(select(ProductVulnerability).where(ProductVulnerability.entry_id == entry.id,
                                                                    ProductVulnerability.product_id == product.id))
            if relation is None:
                relation = ProductVulnerability(entry_id=entry.id, product_id=product.id)
            relation.version_expression = result.get("version_expression")
            relation.version_status = result.get("version_status") or "unknown"
            relation.impact = str(result.get("impact") or "")
            relation.match_confidence = min(1.0, max(0.0, float(result.get("confidence", 0))))
            db.add(relation)
            link_material_to_product(db, material, product,
                                     version_expression=result.get("version_expression"),
                                     version_status=result.get("version_status") or "unknown",
                                     evidence_refs=[]) 
            if (auto_publish or entry.status == "published") and eligible:
                publish_entry(db, entry, store)
        review_task = db.get(AIReviewTask, review_task_id)
        if review_task:
            review_task.state, review_task.result_json, review_task.last_error = "completed", result, None
        db.commit()
        return {"status": material.review_status, "material_id": material.id, "published": entry.status == "published",
                "reasons": failures}
    except Exception as exc:
        db.rollback()
        message = str(exc)[:4000]
        paused = "budget_paused" in message
        retryable = any(category in message for category in ("timeout", "provider_unavailable", "connection_error",
                                                              "rate_limited", "concurrency_limited"))
        material = db.get(MaterialVariant, material.id)
        if material and material.review_status != "approved":
            material.review_status = "budget_paused" if paused else "review_error"
        task_id = db.scalar(select(AIReviewTask.id).where(AIReviewTask.material_id == material.id,
            AIReviewTask.input_sha256 == digest).order_by(AIReviewTask.created_at.desc()).limit(1)) if material else None
        review_task = db.get(AIReviewTask, task_id) if task_id else None
        if retryable and review_task and review_task.attempts >= 5:
            retryable = False
        db.add(AIReview(material_id=material.id, task_id=task_id, model="unavailable",
                        decision="budget_paused" if paused else "review_error",
                        gates={}, evidence={}, error=message))
        if paused or retryable:
            now = utcnow()
            if paused:
                available_at = datetime.combine(now.date() + timedelta(days=1), time.min, tzinfo=timezone.utc)
            else:
                task = review_task
                retry_at = task.available_at.replace(tzinfo=timezone.utc) if task and task.available_at.tzinfo is None else (task.available_at if task else None)
                available_at = retry_at if retry_at and retry_at > now else now + timedelta(seconds=30)
            pending_jobs = db.scalars(select(Job).where(Job.kind == "review_material",
                Job.state.in_(["queued", "running"]))).all()
            already_queued = any((job.payload or {}).get("material_id") == material.id for job in pending_jobs)
            if not already_queued:
                db.add(Job(kind="review_material", payload={"material_id": material.id}, state="queued",
                           available_at=available_at))
        db.commit()
        return {"status": "budget_paused" if paused else "review_error", "material_id": material.id,
                "review_task_id": task_id, "retry_queued": paused or retryable, "error": message[:500]}

