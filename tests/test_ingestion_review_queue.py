from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vuln_kb import ai_review
from vuln_kb.adapters.contracts import RawSnapshot, SourceRef
from vuln_kb.ai_providers import ProviderFailure
from vuln_kb.database import Base
from vuln_kb.ingestion import import_snapshot
from vuln_kb.models import (AIProviderConfig, AIReview, AIReviewTask, AIUsageRecord, Job, KnowledgeEntry,
                            MaterialVariant, ProductVulnerability, PublicationOutbox)
from vuln_kb.security import encrypt_secret
from vuln_kb.storage import ObjectStore


class IngestionReviewQueueTests(unittest.TestCase):
    @staticmethod
    def _eligible_result(content: bytes) -> dict:
        text = content.decode()
        lines = text.splitlines()
        digest = hashlib.sha256(content).hexdigest()
        citations = {}
        for claim, line_no in (("product", 1), ("impact", 5), ("prerequisites", 2),
                               ("instructions", 3), ("success_criteria", 4)):
            citations[claim] = [{"chunk_id": "chunk-0001", "start_line": line_no,
                "end_line": line_no, "source_sha256": digest, "quote": lines[line_no - 1]}]
        return {"decision": "eligible", "title": "Queue Fixture local response disclosure",
            "summary": "A controlled synthetic fixture exposes a response marker.",
            "vuln_type": "information disclosure", "cve_id": None, "cwe_ids": [],
            "company": "Fixture Labs", "product": "Queue Fixture", "product_aliases": [],
            "version_expression": None, "version_status": "unknown", "impact": lines[4],
            "material_kind": "procedure", "language": "text", "prerequisites": lines[1],
            "instructions": lines[2], "success_criteria": lines[3], "tested_versions": None,
            "gates": {"G1_source": "pass", "G2_material": "pass", "G3_prerequisites": "pass",
                      "G4_success_impact": "pass", "G5_usable": "pass"},
            "claim_evidence": citations, "missing_items": [], "evidence_quotes": [],
            "reviewed_chunk_ids": ["chunk-0001"], "confidence": 0.99}

    def test_provider_timeout_keeps_candidate_and_enqueues_retry_with_uncertain_usage(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        content = ("Synthetic public reproduction notes. "
                   "Product: Queue Fixture. Prerequisite: a local test service. "
                   "Steps: submit a harmless marker and inspect the local response. "
                   "Expected result: the response contains the marker. "
                   "Impact: controlled fixture record disclosure.").encode()
        digest = hashlib.sha256(content).hexdigest()
        snapshot = RawSnapshot(SourceRef("github_repo", "owner/repo:path", "fixture procedure",
            "https://github.com/owner/repo/blob/main/repro.txt", {"repo": "owner/repo", "path": "repro.txt"}),
            content, "commit-123")

        class TimeoutProvider:
            def __init__(self, *_args, **_kwargs):
                pass

            async def complete_json(self, _messages, **_kwargs):
                raise ProviderFailure("timeout", "connection timed out", retryable=True)

        with tempfile.TemporaryDirectory() as temp, Session(engine) as db:
            db.add(AIProviderConfig(name="default", base_url="http://localhost:9000/v1", model="mock",
                api_key_ciphertext=encrypt_secret("secret"), enabled=True, auto_publish=True, daily_budget_usd=1))
            db.commit()
            with patch.object(ai_review, "OpenAICompatibleProvider", TimeoutProvider):
                result = asyncio.run(import_snapshot(db, snapshot, ObjectStore(Path(temp) / "objects")))
            self.assertEqual(result["status"], "review_error")
            self.assertTrue(result["retry_queued"])
            material = db.get(MaterialVariant, result["material_id"])
            self.assertEqual(material.review_status, "review_error")
            task = db.scalar(select(AIReviewTask).where(AIReviewTask.material_id == material.id))
            self.assertEqual(task.state, "review_error")
            self.assertEqual(task.attempts, 1)
            usage = db.scalar(select(AIUsageRecord).where(AIUsageRecord.task_id == task.id))
            self.assertEqual(usage.state, "uncertain")
            job = db.scalar(select(Job).where(Job.kind == "review_material", Job.state == "queued"))
            self.assertIsNotNone(job)
            self.assertEqual(job.payload["material_id"], material.id)
            self.assertGreaterEqual(job.available_at, task.available_at.replace(tzinfo=job.available_at.tzinfo))
            review = db.scalar(select(AIReview).where(AIReview.task_id == task.id))
            self.assertEqual(review.decision, "review_error")
        engine.dispose()

    def test_successful_review_publishes_with_task_and_outbox_in_final_transaction(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        content = ("Product: Queue Fixture.\n"
                   "Prerequisite: a local test service is available.\n"
                   "Steps: submit a harmless marker and inspect the local response carefully.\n"
                   "Expected result: the local response contains the submitted marker.\n"
                   "Impact: controlled fixture record disclosure is demonstrated safely.").encode()
        snapshot = RawSnapshot(SourceRef("github_repo", "owner/repo:path", "fixture procedure",
            "https://github.com/owner/repo/blob/main/repro.txt", {"repo": "owner/repo", "path": "repro.txt"}),
            content, "commit-123")
        result_json = self._eligible_result(content)

        class SuccessProvider:
            calls = 0

            def __init__(self, *_args, **_kwargs):
                pass

            async def complete_json(self, _messages, **_kwargs):
                type(self).calls += 1
                return result_json, {"input": 120, "output": 80}

        with tempfile.TemporaryDirectory() as temp, Session(engine) as db:
            provider = SuccessProvider
            config = AIProviderConfig(name="default", base_url="http://localhost:9000/v1", model="mock",
                api_key_ciphertext=encrypt_secret("secret"), enabled=True, auto_publish=True,
                capability_tested_at=__import__("vuln_kb.models", fromlist=["utcnow"]).utcnow(),
                daily_budget_usd=1)
            db.add(config)
            db.commit()
            with patch.object(ai_review, "OpenAICompatibleProvider", provider):
                outcome = asyncio.run(import_snapshot(db, snapshot, ObjectStore(Path(temp) / "objects")))
            self.assertEqual(outcome["status"], "approved")
            self.assertTrue(outcome["published"])
            material = db.get(MaterialVariant, outcome["material_id"])
            entry = db.get(KnowledgeEntry, material.entry_id)
            task = db.scalar(select(AIReviewTask).where(AIReviewTask.material_id == material.id))
            review = db.scalar(select(AIReview).where(AIReview.task_id == task.id))
            outbox = db.scalar(select(PublicationOutbox).where(PublicationOutbox.entry_id == entry.id))
            relation = db.scalar(select(ProductVulnerability).where(ProductVulnerability.entry_id == entry.id))
            self.assertEqual(task.state, "completed")
            self.assertEqual(task.result_json["decision"], "eligible")
            self.assertEqual(review.decision, "eligible")
            self.assertEqual(entry.status, "published")
            self.assertEqual(material.evidence_grade, "material_reviewed")
            self.assertEqual(outbox.event_type, "published")
            self.assertEqual(relation.product.name, "Queue Fixture")
            self.assertEqual(provider.calls, 1)
        engine.dispose()

    def test_failed_rereview_revokes_old_publication_and_emits_outbox(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        content = ("Product: Queue Fixture.\n"
                   "Prerequisite: a local test service is available.\n"
                   "Steps: submit a harmless marker and inspect the local response carefully.\n"
                   "Expected result: the local response contains the submitted marker.\n"
                   "Impact: controlled fixture record disclosure is demonstrated safely.").encode()
        snapshot = RawSnapshot(SourceRef("github_repo", "owner/repo:rereview", "fixture procedure",
            "https://github.com/owner/repo/blob/main/rereview.txt", {"repo": "owner/repo", "path": "rereview.txt"}),
            content, "commit-123")

        class MutableProvider:
            result = self._eligible_result(content)

            def __init__(self, *_args, **_kwargs):
                pass

            async def complete_json(self, _messages, **_kwargs):
                return type(self).result, {"input": 120, "output": 80}

        with tempfile.TemporaryDirectory() as temp, Session(engine) as db:
            config = AIProviderConfig(name="default", base_url="http://localhost:9000/v1", model="mock",
                api_key_ciphertext=encrypt_secret("secret"), enabled=True, auto_publish=True,
                capability_tested_at=__import__("vuln_kb.models", fromlist=["utcnow"]).utcnow(),
                daily_budget_usd=1)
            db.add(config)
            db.commit()
            store = ObjectStore(Path(temp) / "objects")
            with patch.object(ai_review, "OpenAICompatibleProvider", MutableProvider):
                first = asyncio.run(import_snapshot(db, snapshot, store))
                self.assertTrue(first["published"])
                config.configuration_revision += 1
                db.commit()
                MutableProvider.result = self._eligible_result(content)
                MutableProvider.result["decision"] = "reject"
                MutableProvider.result["gates"]["G5_usable"] = "fail"
                second = asyncio.run(import_snapshot(db, snapshot, store, force_review=True))
            self.assertEqual(second["status"], "rejected")
            material = db.get(MaterialVariant, first["material_id"])
            entry = db.get(KnowledgeEntry, material.entry_id)
            self.assertEqual(entry.status, "needs_revalidation")
            self.assertEqual(material.evidence_grade, "unassessed")
            latest_event = db.scalar(select(PublicationOutbox).where(PublicationOutbox.entry_id == entry.id)
                .order_by(PublicationOutbox.publication_revision.desc()))
            self.assertEqual(latest_event.event_type, "material_revoked")
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
