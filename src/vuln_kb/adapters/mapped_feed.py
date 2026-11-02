from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from vuln_kb.adapters.contracts import DiscoveryPage, RawSnapshot, SourceRef
from vuln_kb.adapters.transport import stream_http_bytes

MAX_SOURCE_BYTES = 10 * 1024 * 1024


def _field(value, path: str | None):
    if not path:
        return None
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def load_mapped_sources(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sources = data.get("sources", [])
    result = {}
    for source in sources:
        if isinstance(source, dict) and source.get("key") and source.get("type") in {"rss", "json_feed"}:
            result[str(source["key"])] = source
    return result


class MappedFeedAdapter:
    """Restricted declarative RSS/JSON feed adapter; no arbitrary plugin code or redirects."""

    def __init__(self, config: dict):
        self.config = config
        self.key = str(config["key"])
        self.allowed_hosts = {str(host).lower() for host in config.get("allow_hosts", [])}
        feed_url = str(config.get("feed_url", ""))
        if not self._allowed(feed_url):
            raise ValueError("feed_url must use HTTPS and a host from allow_hosts")

    def _allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme == "https" and (parsed.hostname or "").lower() in self.allowed_hosts

    async def probe(self) -> dict:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
            response = await client.get(self.config["feed_url"], headers={"User-Agent": "VulnKB/0.1 (+source adapter)"})
            response.raise_for_status()
            if len(response.content) > MAX_SOURCE_BYTES:
                raise ValueError("feed exceeds the configured 10 MiB response limit")
        return {"ok": True, "status_code": response.status_code, "source": self.key,
                "content_type": response.headers.get("content-type", "")}

    def _items(self, content: bytes) -> list[dict]:
        if self.config["type"] == "json_feed":
            payload = json.loads(content)
            values = _field(payload, self.config.get("items_path", "items"))
            if not isinstance(values, list):
                raise ValueError("mapped JSON items_path did not resolve to a list")
            return [x for x in values if isinstance(x, dict)]
        root = ET.fromstring(content)
        items = []
        for element in root.iter():
            if element.tag.split("}")[-1].lower() not in {"item", "entry"}:
                continue
            item = {}
            for child in element:
                name = child.tag.split("}")[-1].lower()
                item[name] = child.attrib.get("href") or (child.text or "").strip()
            items.append(item)
        return items

    async def discover(self, partition: str = "", cursor: str | None = None, budget: int = 100) -> DiscoveryPage:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            response = await client.get(self.config["feed_url"], headers={"User-Agent": "VulnKB/0.1 (+source adapter)"})
            response.raise_for_status()
            if len(response.content) > MAX_SOURCE_BYTES:
                raise ValueError("feed exceeds the configured 10 MiB response limit")
        docs = self._items(response.content)
        fields = self.config.get("fields", {})
        offset = int(cursor or 0)
        size = max(1, min(budget, 500))
        batch = docs[offset:offset + size]
        refs = []
        for item in batch:
            external_id = _field(item, fields.get("id"))
            title = _field(item, fields.get("title"))
            source_url = _field(item, fields.get("url"))
            material_url = _field(item, fields.get("material_url")) or source_url
            if not external_id or not source_url or not material_url or not self._allowed(str(source_url)) or not self._allowed(str(material_url)):
                continue
            refs.append(SourceRef(self.key, str(external_id), str(title or external_id)[:500], str(source_url),
                                  {"download_url": str(material_url), "revision": str(_field(item, fields.get("revision")) or "") or None,
                                   "license": str(_field(item, fields.get("license")) or "") or None,
                                   "allowed_hosts": sorted(self.allowed_hosts)}))
        next_offset = offset + len(batch)
        next_cursor = str(next_offset) if next_offset < len(docs) else None
        return DiscoveryPage(refs, next_cursor, next_cursor is None)

    async def fetch(self, ref: SourceRef) -> RawSnapshot:
        url = ref.metadata.get("download_url", "")
        if not self._allowed(url):
            raise ValueError("refuses non-allowlisted feed material URL")
        return RawSnapshot(ref, stream_http_bytes(url, headers={"User-Agent": "VulnKB/0.1 (+source adapter)"},
                                                  max_bytes=MAX_SOURCE_BYTES, timeout=45),
                           ref.metadata.get("revision"), ref.metadata.get("license"))

