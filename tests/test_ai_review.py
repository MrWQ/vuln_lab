from __future__ import annotations

import asyncio
import hashlib
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from vuln_kb import ai_review
from vuln_kb.ai_review import build_source_chunks, verify_claim_evidence
from vuln_kb.database import Base
from vuln_kb.models import (AIProviderConfig, AIReviewTask, AIUsageRecord, KnowledgeEntry,
                            MaterialVariant, Organization, Product, SourceDocument)
from vuln_kb.security import encrypt_secret


class AIReviewEvidenceTests(unittest.TestCase):
    def test_chunks_reconstruct_source_without_gaps_or_truncation(self) -> None:
        source = ("第一段内容\n" * 2000) + "尾部证据 Acme Product 和复现判据。"
        chunks = build_source_chunks(source, chunk_chars=257)
        self.assertEqual("".join(chunk["text"] for chunk in chunks), source)
        self.assertEqual(chunks[0]["start_char"], 0)
        self.assertEqual(chunks[-1]["end_char"], len(source))
        self.assertGreater(len(chunks), 10)

    def test_citation_hash_chunk_and_source_line_are_verified(self) -> None:
        source = "ignored\nProduct: Example Widget\nImpact: controlled fixture data disclosure\n"
        digest = hashlib.sha256(source.encode()).hexdigest()
        chunk = build_source_chunks(source)[0]
        quote = "Product: Example Widget"
        result = {"claim_evidence": {"product": [{"chunk_id": chunk["chunk_id"], "start_line": 2,
            "end_line": 2, "source_sha256": digest, "quote": quote}],
            "impact": [], "prerequisites": [], "instructions": [], "success_criteria": [], "version": []}}
        verified, failures = verify_claim_evidence(result, source, digest, [chunk])
        self.assertEqual(verified["product"][0]["quote"], quote)
        self.assertTrue(any("impact 缺少" in error for error in failures))
        result["claim_evidence"]["product"][0]["start_line"] = 1
        _, failures = verify_claim_evidence(result, source, digest, [chunk])
        self.assertTrue(any("行号" in error for error in failures))
        result["claim_evidence"]["product"][0]["start_line"] = 2
        result["claim_evidence"]["product"][0]["source_sha256"] = "0" * 64
        _, failures = verify_claim_evidence(result, source, digest, [chunk])
        self.assertTrue(any("哈希" in error for error in failures))

    def test_review_sends_complete_long_source_and_rejects_over_limit_without_calling_provider(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        tail = ("Product: Long Tail Product. Impact: controlled disclosure of a local fixture record. "
                "Prerequisite: a local test instance and test account. "
                "Instructions: submit the benign fixture marker and inspect the local response. "
                "Success criteria: the expected fixture marker appears in the response.")
        source = ("padding note without product claims\n" * 5000) + tail + "\n"
        digest = hashlib.sha256(source.encode()).hexdigest()
        captured = {}

        class FakeProvider:
            def __init__(self, _url, model, _key, *, timeout):
                captured["model"] = model

            async def complete_json(self, messages, *, max_tokens=2048):
                captured["calls"] = captured.get("calls", 0) + 1
                prompt = __import__("json").loads(messages[1]["content"])
                chunks = prompt["source"]["chunks"]
                captured["source"] = "".join(chunk["text"] for chunk in chunks)
                captured["chunks"] = chunks
                self_citation = {"chunk_id": chunks[-1]["chunk_id"],
                                 "start_line": source.count("\n", 0, source.index(tail)) + 1,
                                 "end_line": source.count("\n", 0, source.index(tail)) + 1,
                                 "source_sha256": digest, "quote": tail}
                return ({"decision": "eligible", "title": "Synthetic long source", "summary": "Long source fixture",
                    "vuln_type": "demo", "cve_id": None, "cwe_ids": [], "company": "Example",
                    "product": "Long Tail Product", "product_aliases": [], "version_expression": None,
                    "version_status": "unknown", "impact": "controlled disclosure of a local fixture record",
                    "material_kind": "procedure", "language": None, "prerequisites": "A local test instance and account.",
                    "instructions": "Submit a marker and inspect the response.",
                    "success_criteria": "The expected fixture marker appears.", "tested_versions": None,
                    "gates": {key: "pass" for key in ("G1_source", "G2_material", "G3_prerequisites",
                                                         "G4_success_impact", "G5_usable")},
                    "claim_evidence": {key: [self_citation] for key in ("product", "impact", "prerequisites",
                                        "instructions", "success_criteria")} | {"version": []},
                    "missing_items": [],
                    "evidence_quotes": [], "reviewed_chunk_ids": [chunk["chunk_id"] for chunk in chunks],
                    "confidence": 0.95}, {"input": 123, "output": 45})

        with Session(engine) as db:
            db.add(AIProviderConfig(name="default", base_url="http://localhost:9000/v1", model="mock",
                                    api_key_ciphertext=encrypt_secret("secret"), enabled=True,
                                    daily_budget_usd=10))
            db.commit()
            material = MaterialVariant(id="material-long", entry_id="entry", source_document_id=1,
                material_kind="procedure", source_url="https://github.com/example/repro",
                sha256=digest, object_key="candidate/sha256/00/" + digest)
            with patch.object(ai_review, "OpenAICompatibleProvider", FakeProvider):
                result, input_tokens, output_tokens, _, task_id = asyncio.run(ai_review.review_material(db, material, source, digest))
            self.assertEqual(captured["source"], source)
            self.assertGreater(len(source), 80_000)
            self.assertIn(tail, captured["source"])
            self.assertEqual(result["reviewed_chunk_ids"], [c["chunk_id"] for c in captured["chunks"]])
            self.assertEqual((input_tokens, output_tokens), (123, 45))
            task = db.get(AIReviewTask, task_id)
            self.assertEqual(task.state, "running")
            usage = db.query(AIUsageRecord).filter_by(task_id=task_id).one()
            self.assertEqual(usage.state, "settled")
            _, _, _, _, cached_task_id = asyncio.run(ai_review.review_material(db, material, source, digest))
            self.assertEqual(cached_task_id, task_id)
            self.assertEqual(captured["calls"], 1)

            with patch.object(ai_review, "settings", type("Settings", (), {"ai_max_review_source_chars": 8})()), \
                 patch.object(ai_review, "OpenAICompatibleProvider", side_effect=AssertionError("provider must not run")):
                with self.assertRaisesRegex(ai_review.ReviewError, "evidence_coverage_incomplete"):
                    asyncio.run(ai_review.review_material(db, material, source, digest))
        engine.dispose()

    def test_timeout_keeps_uncertain_budget_reservation_and_rpm_defers_retry(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        source = "synthetic retry source with full material evidence and one complete procedure"
        digest = hashlib.sha256(source.encode()).hexdigest()
        calls = []

        class TimeoutProvider:
            def __init__(self, *_args, **_kwargs):
                pass

            async def complete_json(self, _messages, **_kwargs):
                calls.append(1)
                from vuln_kb.ai_providers import ProviderFailure
                raise ProviderFailure("timeout", "connection timed out", retryable=True)

        with Session(engine) as db:
            db.add(AIProviderConfig(name="default", base_url="http://localhost:9000/v1", model="mock",
                api_key_ciphertext=encrypt_secret("secret"), enabled=True, daily_budget_usd=1,
                requests_per_minute=1, max_concurrent_reviews=1))
            db.commit()
            material = MaterialVariant(id="material-retry", entry_id="entry", source_document_id=1,
                material_kind="procedure", source_url="https://github.com/example/retry", sha256=digest,
                object_key="candidate/sha256/00/" + digest)
            with patch.object(ai_review, "OpenAICompatibleProvider", TimeoutProvider):
                with self.assertRaisesRegex(ai_review.ReviewError, "timeout"):
                    asyncio.run(ai_review.review_material(db, material, source, digest))
                task = db.query(AIReviewTask).one()
                usage = db.query(AIUsageRecord).one()
                self.assertEqual((task.state, task.attempts), ("review_error", 1))
                self.assertEqual(usage.state, "uncertain")
                self.assertGreaterEqual(usage.reserved_cost_usd, usage.actual_cost_usd)
                with self.assertRaisesRegex(ai_review.ReviewError, "rate_limited"):
                    asyncio.run(ai_review.review_material(db, material, source, digest))
                db.refresh(task)
                self.assertEqual(task.state, "queued")
                self.assertEqual(task.attempts, 1)
                self.assertEqual(len(calls), 1)
        engine.dispose()

    def test_budget_exhaustion_persists_pause_without_model_call_or_rejection(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        source = "long-enough " * 200
        digest = hashlib.sha256(source.encode()).hexdigest()

        class NeverCalled:
            def __init__(self, *_args, **_kwargs):
                raise AssertionError("budget must pause before calling the provider")

        with Session(engine) as db:
            db.add(AIProviderConfig(name="default", base_url="https://model.example/v1", model="remote",
                api_key_ciphertext=encrypt_secret("secret"), enabled=True, daily_budget_usd=0.000001,
                input_price_per_million=1, output_price_per_million=1))
            db.commit()
            material = MaterialVariant(id="material-budget", entry_id="entry", source_document_id=1,
                material_kind="procedure", source_url="https://github.com/example/budget", sha256=digest,
                object_key="candidate/sha256/00/" + digest)
            with patch.object(ai_review, "OpenAICompatibleProvider", NeverCalled):
                with self.assertRaisesRegex(ai_review.ReviewError, "budget_paused"):
                    asyncio.run(ai_review.review_material(db, material, source, digest))
            task = db.query(AIReviewTask).one()
            self.assertEqual(task.state, "budget_paused")
            self.assertEqual(task.attempts, 0)
            self.assertEqual(db.query(AIUsageRecord).count(), 0)
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
