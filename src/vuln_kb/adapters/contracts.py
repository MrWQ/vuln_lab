from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterable, Protocol


@dataclass(frozen=True)
class SourceRef:
    source_key: str
    external_id: str
    title: str
    url: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DiscoveryPage:
    items: list[SourceRef]
    next_cursor: str | None = None
    exhausted: bool = False


@dataclass(frozen=True)
class RawSnapshot:
    ref: SourceRef
    content: bytes | AsyncIterable[bytes]
    revision: str | None
    license_hint: str | None = None


class SourceAdapter(Protocol):
    key: str
    async def probe(self) -> dict[str, Any]: ...
    async def discover(self, partition: str, cursor: str | None = None, budget: int = 100) -> DiscoveryPage: ...
    async def fetch(self, ref: SourceRef) -> RawSnapshot: ...

