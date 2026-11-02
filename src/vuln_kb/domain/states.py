"""Explicit state transition rules; source and material review are independent."""

from __future__ import annotations

from vuln_kb.domain.contracts import MaterialReviewState, PublicationState

PUBLICATION_TRANSITIONS: dict[PublicationState, frozenset[PublicationState]] = {
    PublicationState.DISCOVERED: frozenset({PublicationState.PREFILTERED, PublicationState.NEEDS_MATERIAL, PublicationState.REJECTED}),
    PublicationState.PREFILTERED: frozenset({PublicationState.MATERIAL_READY, PublicationState.NEEDS_MATERIAL, PublicationState.REJECTED}),
    PublicationState.MATERIAL_READY: frozenset({PublicationState.IN_REVIEW, PublicationState.NEEDS_MATERIAL, PublicationState.REJECTED}),
    PublicationState.IN_REVIEW: frozenset({PublicationState.PUBLISHED, PublicationState.NEEDS_MATERIAL, PublicationState.REJECTED}),
    PublicationState.NEEDS_MATERIAL: frozenset({PublicationState.PREFILTERED, PublicationState.MATERIAL_READY, PublicationState.IN_REVIEW, PublicationState.REJECTED}),
    PublicationState.PUBLISHED: frozenset({PublicationState.NEEDS_REVALIDATION, PublicationState.WITHDRAWN}),
    PublicationState.NEEDS_REVALIDATION: frozenset({PublicationState.IN_REVIEW, PublicationState.PUBLISHED, PublicationState.WITHDRAWN}),
    PublicationState.REJECTED: frozenset({PublicationState.PREFILTERED, PublicationState.NEEDS_MATERIAL}),
    PublicationState.WITHDRAWN: frozenset({PublicationState.IN_REVIEW}),
}

MATERIAL_TRANSITIONS: dict[MaterialReviewState, frozenset[MaterialReviewState]] = {
    MaterialReviewState.PENDING: frozenset({MaterialReviewState.REVIEWING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.REVIEWING: frozenset({MaterialReviewState.APPROVED, MaterialReviewState.NEEDS_MATERIAL,
                                                MaterialReviewState.REJECTED, MaterialReviewState.REVIEW_ERROR,
                                                MaterialReviewState.BUDGET_PAUSED, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.REVIEW_ERROR: frozenset({MaterialReviewState.PENDING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.BUDGET_PAUSED: frozenset({MaterialReviewState.PENDING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.NEEDS_MATERIAL: frozenset({MaterialReviewState.PENDING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.APPROVED: frozenset({MaterialReviewState.PENDING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.REJECTED: frozenset({MaterialReviewState.PENDING, MaterialReviewState.SUPERSEDED}),
    MaterialReviewState.SUPERSEDED: frozenset(),
}


def can_transition(current: PublicationState | MaterialReviewState,
                   target: PublicationState | MaterialReviewState) -> bool:
    """Return whether a transition is legal without conflating the two state axes."""
    if isinstance(current, PublicationState) and isinstance(target, PublicationState):
        return target in PUBLICATION_TRANSITIONS[current]
    if isinstance(current, MaterialReviewState) and isinstance(target, MaterialReviewState):
        return target in MATERIAL_TRANSITIONS[current]
    return False


def require_transition(current: PublicationState | MaterialReviewState,
                       target: PublicationState | MaterialReviewState) -> None:
    if not can_transition(current, target):
        raise ValueError(f"illegal state transition: {current.value} -> {target.value}")

