from __future__ import annotations

import json
import hashlib
import unittest
from pathlib import Path

from vuln_kb.adapters.contracts import SourceRef, RawSnapshot
from vuln_kb.ai_review import build_source_chunks
from vuln_kb.domain.contracts import ContractEnvelope, GateSet, GateResult, GateStatus, MaterialAssessment
from vuln_kb.ingestion import _gate_passed
from vuln_kb.domain.contracts import (
    CONTRACT_VERSION, ContractEnvelope, MaterialReviewState, PublicationState,
    ReasonCode, REASON_POLICY, VulnerabilityRecord,
)
from vuln_kb.domain.states import can_transition

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "admission_cases.json"


def load_cases() -> list[dict]:
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if document["fixture_version"] != CONTRACT_VERSION:
        raise AssertionError("fixture version must track the domain contract version")
    return document["cases"]


def resolve_product(name: str, candidates: list[dict]) -> str:
    matches = [item for item in candidates if item["name"].casefold() == name.casefold()]
    if len(matches) != 1:
        return "ambiguous" if matches else "unidentified"
    return matches[0]["organization"]


def unique_materials(materials: list[dict]) -> list[dict]:
    by_hash: dict[str, dict] = {}
    for material in materials:
        by_hash.setdefault(material["sha256"].lower(), material)
    return list(by_hash.values())


def evaluate_fixture(case: dict) -> dict:
    """Small deterministic oracle for the declared fixture expectations."""
    source = case.get("source", {})
    expected = {"reason_codes": [], "search_products": [], "material_count": 0}
    if source.get("fetch_error"):
        return {**expected, "publication_state": "needs_material", "material_state": "review_error",
                "reason_codes": ["source_material_unavailable"], "retryable": True}
    materials = unique_materials(case.get("materials", []))
    if not materials:
        return {**expected, "publication_state": "needs_material", "material_state": "needs_material",
                "reason_codes": ["material_missing"]}
    product_names = [product["name"] for product in case.get("products", [])]
    text = source.get("text") or ""
    named_matches = [name for name in set(product_names) if name.casefold() in text.casefold()]
    if any(sum(name.casefold() == candidate.casefold() for candidate in product_names) > 1 for name in named_matches):
        return {**expected, "publication_state": "in_review", "material_state": "needs_material",
                "reason_codes": ["product_ambiguous"]}
    if any(quote not in text for quote in case.get("evidence_quotes", [])):
        return {**expected, "publication_state": "needs_material", "material_state": "needs_material",
                "reason_codes": ["evidence_quote_invalid"]}
    if len(case.get("sources", [])) > 1:
        expected["reason_codes"].append("duplicate_material")
        expected["source_assertion_count"] = len(case["sources"])
    expected["publication_state"] = "published"
    expected["material_state"] = "approved"
    expected["material_count"] = len(materials)
    expected["search_products"] = product_names
    return expected


class ContractFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {case["id"]: case for case in load_cases()}

    def test_contract_version_and_reason_policy_are_complete(self) -> None:
        self.assertEqual(CONTRACT_VERSION, "1.0.0")
        self.assertEqual(set(REASON_POLICY), set(ReasonCode))
        self.assertFalse(REASON_POLICY[ReasonCode.VERSION_UNKNOWN][0])
        self.assertTrue(REASON_POLICY[ReasonCode.SOURCE_UNAVAILABLE][1])

    def test_checked_in_json_schema_matches_executable_contract(self) -> None:
        schema_path = Path(__file__).parents[1] / "schemas" / "contract-v1.json"
        actual = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(actual, ContractEnvelope.model_json_schema())

    def test_g6_is_required_in_final_contract_and_material_scope_is_explicit(self) -> None:
        self.assertIn("G6_review_complete", ContractEnvelope.model_json_schema()["$defs"]["GateSet"]["required"])
        record = VulnerabilityRecord.model_validate({
            "record_id": "synthetic-multi", "title": "Synthetic multi product",
            "publication_state": "published",
            "products": [{"name": "Acme Cache"}, {"name": "Beta Cache"}],
            "materials": [{"material_id": "m1", "material_kind": "procedure",
                           "source": {"source_key": "fixture", "external_id": "x", "url": "https://fixture.invalid/x"},
                           "sha256": "a" * 64, "size_bytes": 4,
                           "applicability": [{"product_ref": "Acme Cache"}],
                           "package": {"prerequisites": "local", "instructions": "step", "success_criteria": "marker"},
                           "review_state": "approved", "evidence_grade": "material_reviewed"}],
        })
        self.assertEqual(len(record.products), 2)
        self.assertEqual(record.materials[0].applicability[0].product_ref, "Acme Cache")
        self.assertEqual(record.publication_revision, 1)

    def test_ai_assessment_cannot_claim_server_gate_or_lab_execution(self) -> None:
        raw = {"material_id": "m1", "model": "fixture-model", "rubric_version": "admission-1.2",
               "decision": "eligible", "confidence": 0.9,
               "gates": {name: {"status": "pass"} for name in (
                   "G1_source", "G2_material", "G3_prerequisites", "G4_success_impact", "G5_usable")}}
        assessment = MaterialAssessment.model_validate(raw)
        self.assertEqual(assessment.proposed_evidence_grade, "material_reviewed")
        raw["proposed_evidence_grade"] = "lab_verified"
        with self.assertRaises(ValueError):
            MaterialAssessment.model_validate(raw)

    def test_rejects_published_record_without_approved_implementation(self) -> None:
        with self.assertRaises(ValueError):
            VulnerabilityRecord.model_validate({"record_id": "no-material", "title": "No material",
                                                "publication_state": "published"})

    def test_empty_repository_does_not_publish(self) -> None:
        case = self.cases["empty-repository"]
        self.assertEqual(case["expected"]["publication_state"], "needs_material")
        self.assertEqual(case["materials"], [])

    def test_stale_source_is_retryable_not_content_rejection(self) -> None:
        expected = self.cases["stale-material-link"]["expected"]
        code = ReasonCode(expected["reason_codes"][0])
        self.assertTrue(REASON_POLICY[code][1])
        self.assertNotEqual(expected["publication_state"], PublicationState.REJECTED.value)

    def test_ambiguous_same_name_stays_unresolved(self) -> None:
        case = self.cases["ambiguous-product-name"]
        self.assertEqual(resolve_product("Widget", case["products"]), "ambiguous")
        self.assertEqual(case["expected"]["search_products"], [])

    def test_fabricated_quote_does_not_match_source(self) -> None:
        case = self.cases["fabricated-evidence-quote"]
        source = case["source"]["text"]
        self.assertTrue(all(quote not in source for quote in case["evidence_quotes"]))
        self.assertIn("evidence_quote_invalid", case["expected"]["reason_codes"])

    def test_material_gate_checks_claim_quotes_against_fetched_source(self) -> None:
        source_text = (
            "Product is Acme Cache. Prerequisite is a local test account. "
            "Run the documented steps against the local fixture only. "
            "Expected output is a fixture marker. Impact is unauthorized local record access."
        )
        ref = SourceRef("fixture", "good", "Synthetic procedure", "https://github.com/example/fixture",
                        {"allowed_hosts": ["github.com"]})
        snapshot = RawSnapshot(ref, source_text.encode(), "fixture-rev")
        source_sha256 = hashlib.sha256(source_text.encode()).hexdigest()
        chunk = build_source_chunks(source_text)[0]
        def citation(quote):
            start = source_text.index(quote)
            line = source_text.count("\n", 0, start) + 1
            return {"chunk_id": chunk["chunk_id"], "start_line": line,
                    "end_line": line + quote.count("\n"), "source_sha256": source_sha256, "quote": quote}
        result = {
            "title": "Synthetic local fixture", "summary": "Synthetic contract sample",
            "company": "Acme", "product": "Acme Cache", "version_expression": None,
            "prerequisites": "A local test account is required.",
            "instructions": "Run the documented steps against the local fixture only.",
            "success_criteria": "Expected output is a fixture marker.",
            "impact": "Impact is unauthorized local record access.", "confidence": 0.9,
            "gates": {name: "pass" for name in ("G1_source", "G2_material", "G3_prerequisites", "G4_success_impact", "G5_usable")},
            "claim_evidence": {
                "product": [citation("Product is Acme Cache")],
                "impact": [citation("Impact is unauthorized local record access")],
                "prerequisites": [citation("Prerequisite is a local test account")],
                "instructions": [citation("Run the documented steps against the local fixture only")],
                "success_criteria": [citation("Expected output is a fixture marker")],
            },
        }
        passed, _, failures = _gate_passed(result, source_text, snapshot, len(source_text))
        self.assertTrue(passed, failures)
        fabricated = citation("Impact is unauthorized local record access")
        fabricated["quote"] = "The source proves arbitrary remote access"
        result["claim_evidence"]["impact"] = [fabricated]
        passed, _, failures = _gate_passed(result, source_text, snapshot, len(source_text))
        self.assertFalse(passed)
        self.assertTrue(any("impact 缺少精确原文证据" in failure for failure in failures))

    def test_fixture_sources_parse_to_existing_adapter_contract(self) -> None:
        for case in self.cases.values():
            sources = case.get("sources", [case.get("source", {})])
            for source in sources:
                ref = SourceRef(source["source_key"], source["external_id"], case["id"], source["url"])
                self.assertTrue(ref.source_key)
                if source.get("fetch_error"):
                    self.assertIsNone(source.get("text"))

    def test_duplicate_reposts_preserve_sources_and_deduplicate_material_hash(self) -> None:
        case = self.cases["duplicate-repost-same-material"]
        self.assertEqual(len(case["sources"]), 2)
        self.assertEqual(len(unique_materials(case["sources"])), 1)
        self.assertEqual(case["expected"]["material_count"], 1)
        self.assertEqual(case["expected"]["source_assertion_count"], 2)

    def test_multiple_products_keep_material_applicability_separate(self) -> None:
        case = self.cases["multiple-products-multiple-implementations"]
        products = {item["name"] for item in case["products"]}
        covered = {product for material in case["materials"] for product in material["applicability"]}
        self.assertEqual(products, covered)
        self.assertEqual(case["expected"]["material_count"], 2)

    def test_state_axes_are_independent_and_illegal_publish_shortcut_is_blocked(self) -> None:
        self.assertTrue(can_transition(PublicationState.IN_REVIEW, PublicationState.PUBLISHED))
        self.assertFalse(can_transition(PublicationState.DISCOVERED, PublicationState.PUBLISHED))
        self.assertFalse(can_transition(MaterialReviewState.BUDGET_PAUSED, MaterialReviewState.REJECTED))

    def test_fixture_search_expectations_only_contain_published_products(self) -> None:
        for case in self.cases.values():
            expected = case["expected"]
            if expected["publication_state"] != "published":
                self.assertEqual(expected["search_products"], [], case["id"])

    def test_all_fixture_outcomes_match_declared_state_and_search_expectations(self) -> None:
        for case in self.cases.values():
            observed = evaluate_fixture(case)
            expected = case["expected"]
            for key in ("publication_state", "material_state", "reason_codes", "search_products", "material_count"):
                self.assertEqual(observed.get(key), expected.get(key), f"fixture={case['id']} field={key}")
            if "retryable" in expected:
                self.assertEqual(observed["retryable"], expected["retryable"], case["id"])
            if "source_assertion_count" in expected:
                self.assertEqual(observed["source_assertion_count"], expected["source_assertion_count"], case["id"])


if __name__ == "__main__":
    unittest.main()
