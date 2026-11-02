"""Version 1 canonical vulnerability/material review contract.

Adapters and AI providers produce these objects; only the application service
may turn an accepted material into a published entry.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

CONTRACT_VERSION = "1.0.0"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


class GateStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class GateId(StrEnum):
    SOURCE = "G1_source"
    MATERIAL = "G2_material"
    SCENARIO = "G3_prerequisites"
    RESULT = "G4_success_impact"
    REUSE = "G5_usable"
    REVIEW = "G6_review_complete"


class PublicationState(StrEnum):
    DISCOVERED = "discovered"
    PREFILTERED = "prefiltered"
    MATERIAL_READY = "material_ready"
    IN_REVIEW = "in_review"
    NEEDS_MATERIAL = "needs_material"
    PUBLISHED = "published"
    NEEDS_REVALIDATION = "needs_revalidation"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class MaterialReviewState(StrEnum):
    PENDING = "pending"
    REVIEWING = "reviewing"
    APPROVED = "approved"
    NEEDS_MATERIAL = "needs_material"
    REJECTED = "rejected"
    REVIEW_ERROR = "review_error"
    BUDGET_PAUSED = "budget_paused"
    SUPERSEDED = "superseded"


class EvidenceGrade(StrEnum):
    UNASSESSED = "unassessed"
    MATERIAL_REVIEWED = "material_reviewed"
    EVIDENCE_REVIEWED = "evidence_reviewed"
    LAB_VERIFIED = "lab_verified"


class ReasonCode(StrEnum):
    SOURCE_UNAVAILABLE = "source_material_unavailable"
    SOURCE_NOT_TRACEABLE = "source_not_traceable"
    SOURCE_NOT_ALLOWED = "source_host_not_allowed"
    MATERIAL_EMPTY = "material_empty"
    MATERIAL_MISSING = "material_missing"
    MATERIAL_INCOMPLETE = "material_incomplete"
    SCENARIO_UNCLEAR = "scenario_unclear"
    SUCCESS_CRITERIA_MISSING = "success_criteria_missing"
    IMPACT_UNSUPPORTED = "impact_unsupported"
    USAGE_UNCLEAR = "usage_unclear"
    PRODUCT_UNIDENTIFIED = "product_unidentified"
    PRODUCT_AMBIGUOUS = "product_ambiguous"
    VERSION_UNKNOWN = "version_unknown"
    EVIDENCE_QUOTE_INVALID = "evidence_quote_invalid"
    EVIDENCE_COVERAGE_INCOMPLETE = "evidence_coverage_incomplete"
    MATERIAL_HASH_MISMATCH = "material_hash_mismatch"
    MODEL_OUTPUT_INVALID = "model_output_invalid"
    MODEL_REJECTED = "model_rejected"
    MODEL_UNAVAILABLE = "model_unavailable"
    BUDGET_PAUSED = "budget_paused"
    DUPLICATE_MATERIAL = "duplicate_material"
    NO_QUALIFIED_MATERIAL = "no_qualified_material"
    POLICY_VERSION_UNSUPPORTED = "policy_version_unsupported"


# Policy separates content rejection from operational retry. Unknown versions are
# non-blocking unless another gate says the applicability cannot be established.
REASON_POLICY: dict[ReasonCode, tuple[bool, bool]] = {
    ReasonCode.SOURCE_UNAVAILABLE: (True, True),
    ReasonCode.SOURCE_NOT_TRACEABLE: (True, False),
    ReasonCode.SOURCE_NOT_ALLOWED: (True, False),
    ReasonCode.MATERIAL_EMPTY: (True, False),
    ReasonCode.MATERIAL_MISSING: (True, True),
    ReasonCode.MATERIAL_INCOMPLETE: (True, True),
    ReasonCode.SCENARIO_UNCLEAR: (True, True),
    ReasonCode.SUCCESS_CRITERIA_MISSING: (True, True),
    ReasonCode.IMPACT_UNSUPPORTED: (True, True),
    ReasonCode.USAGE_UNCLEAR: (True, True),
    ReasonCode.PRODUCT_UNIDENTIFIED: (True, True),
    ReasonCode.PRODUCT_AMBIGUOUS: (True, True),
    ReasonCode.VERSION_UNKNOWN: (False, False),
    ReasonCode.EVIDENCE_QUOTE_INVALID: (True, False),
    ReasonCode.EVIDENCE_COVERAGE_INCOMPLETE: (True, True),
    ReasonCode.MATERIAL_HASH_MISMATCH: (True, True),
    ReasonCode.MODEL_OUTPUT_INVALID: (True, True),
    ReasonCode.MODEL_REJECTED: (True, False),
    ReasonCode.MODEL_UNAVAILABLE: (True, True),
    ReasonCode.BUDGET_PAUSED: (True, True),
    ReasonCode.DUPLICATE_MATERIAL: (False, False),
    ReasonCode.NO_QUALIFIED_MATERIAL: (True, True),
    ReasonCode.POLICY_VERSION_UNSUPPORTED: (True, False),
}

assert set(REASON_POLICY) == set(ReasonCode), "every reason code must define blocking/retry behavior"


class Reason(StrictModel):
    code: ReasonCode
    blocking: bool
    retryable: bool = False
    detail: str = Field(min_length=1, max_length=1200)


class OrganizationRef(StrictModel):
    name: str = Field(min_length=1, max_length=240)
    aliases: list[str] = Field(default_factory=list)
    external_ids: dict[str, str] = Field(default_factory=dict)


class ProductRef(StrictModel):
    name: str = Field(min_length=1, max_length=300)
    organization: OrganizationRef | None = None
    aliases: list[str] = Field(default_factory=list)
    ecosystem: str | None = Field(default=None, max_length=80)
    external_ids: dict[str, str] = Field(default_factory=dict)


class Applicability(StrictModel):
    product_ref: str = Field(min_length=1, description="Stable product ID or contract-local reference")
    version_expression: str | None = Field(default=None, max_length=500)
    version_status: Literal["affected", "not_affected", "unknown", "not_applicable"] = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)


class SourceAssertion(StrictModel):
    source_key: str = Field(min_length=1, max_length=80)
    external_id: str = Field(min_length=1, max_length=800)
    url: HttpUrl
    revision: str | None = Field(default=None, max_length=240)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    license_hint: str | None = Field(default=None, max_length=300)
    public: bool = True


class EvidenceRef(StrictModel):
    evidence_id: str = Field(min_length=1, max_length=120)
    source_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    locator: str = Field(min_length=1, max_length=500, description="Line range, JSON pointer, or paragraph anchor")
    quote: str = Field(min_length=1, max_length=4000)
    claim: str = Field(min_length=1, max_length=120)


class MissingItem(StrictModel):
    code: ReasonCode
    blocking: bool
    detail: str = Field(min_length=1, max_length=1200)
    suggested_action: str | None = Field(default=None, max_length=1200)


class GateResult(StrictModel):
    status: GateStatus
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ModelGateSet(StrictModel):
    G1_source: GateResult
    G2_material: GateResult
    G3_prerequisites: GateResult
    G4_success_impact: GateResult
    G5_usable: GateResult
    # G6 is deliberately absent: a model cannot approve its own audit.


class GateSet(ModelGateSet):
    """Persisted six-gate result after deterministic server-side G6 evaluation."""
    G6_review_complete: GateResult


class MaterialAssessment(StrictModel):
    """A versioned AI assessment; its G6 outcome is attached only by the server."""
    material_id: str = Field(min_length=1, max_length=120)
    model: str = Field(min_length=1, max_length=200)
    rubric_version: str = Field(min_length=1, max_length=80)
    decision: Literal["eligible", "needs_review", "reject"]
    gates: ModelGateSet
    evidence_refs: list[str] = Field(default_factory=list)
    missing_items: list[MissingItem] = Field(default_factory=list)
    proposed_evidence_grade: Literal["material_reviewed", "evidence_reviewed"] = "material_reviewed"
    confidence: float = Field(ge=0, le=1)


class ReproductionPackage(StrictModel):
    prerequisites: str = Field(min_length=1, max_length=20000)
    instructions: str = Field(min_length=1, max_length=100000)
    success_criteria: str = Field(min_length=1, max_length=10000)
    tested_versions: str | None = Field(default=None, max_length=500)
    execution_recorded: bool = False


class MaterialImplementation(StrictModel):
    material_id: str = Field(min_length=1, max_length=120)
    material_kind: Literal["poc", "exp", "procedure", "other"]
    language: str | None = Field(default=None, max_length=80)
    source: SourceAssertion
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(ge=0)
    applicability: list[Applicability] = Field(min_length=1)
    package: ReproductionPackage | None = None
    review_state: MaterialReviewState = MaterialReviewState.PENDING
    evidence_grade: EvidenceGrade = EvidenceGrade.UNASSESSED
    gates: GateSet | None = None

    @model_validator(mode="after")
    def package_for_material_ready(self) -> "MaterialImplementation":
        if self.review_state == MaterialReviewState.APPROVED and self.package is None:
            raise ValueError("approved material requires a reproduction package")
        if self.evidence_grade == EvidenceGrade.LAB_VERIFIED and not (self.package and self.package.execution_recorded):
            raise ValueError("lab_verified requires a recorded independent execution")
        return self


class VulnerabilityRecord(StrictModel):
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    record_id: str = Field(min_length=1, max_length=120)
    entry_type: Literal["case", "method"] = "case"
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(default="", max_length=10000)
    products: list[ProductRef] = Field(default_factory=list)
    applicability: list[Applicability] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    vulnerability_type: str | None = Field(default=None, max_length=160)
    publication_state: PublicationState = PublicationState.DISCOVERED
    publication_revision: int = Field(default=1, ge=1)
    materials: list[MaterialImplementation] = Field(default_factory=list)
    source_assertions: list[SourceAssertion] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    review_assessments: list[MaterialAssessment] = Field(default_factory=list)
    reasons: list[Reason] = Field(default_factory=list)
    policy_version: str = Field(default="admission-1.2", min_length=1, max_length=80)

    @model_validator(mode="after")
    def published_record_has_qualified_material(self) -> "VulnerabilityRecord":
        if self.publication_state == PublicationState.PUBLISHED:
            approved = [m for m in self.materials if m.review_state == MaterialReviewState.APPROVED]
            if not approved:
                raise ValueError("published record requires at least one approved material implementation")
            if not self.products and self.entry_type == "case":
                raise ValueError("published case requires at least one product identity")
        return self


class ContractEnvelope(StrictModel):
    contract_version: Literal["1.0.0"] = CONTRACT_VERSION
    records: list[VulnerabilityRecord]

