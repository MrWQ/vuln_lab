from __future__ import annotations

import base64
import json
import re

import httpx

from vuln_kb.adapters.contracts import DiscoveryPage, RawSnapshot, SourceRef
from vuln_kb.adapters.transport import stream_http_bytes
from vuln_kb.config import settings

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
MATERIAL_SUFFIXES = {".py", ".rb", ".php", ".js", ".ts", ".go", ".java", ".sh", ".pl", ".md", ".txt", ".yaml", ".yml", ".json", ".c", ".cpp", ".ps1"}


class GitHubAdapter:
    key = "github_repo"

    def __init__(self, repo: str, token: str | None = None):
        parts = repo.strip("/").split("/")
        if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts):
            raise ValueError("repo must be owner/name")
        self.owner, self.name = parts
        self.token = token if token is not None else settings.github_token
        self.headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    async def probe(self) -> dict:
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            response = await client.get(f"{API}/repos/{self.owner}/{self.name}", headers=self.headers)
            response.raise_for_status()
            data = response.json()
        if data.get("private"):
            raise ValueError("只允许接入公开 GitHub 仓库")
        return {"ok": True, "default_branch": data.get("default_branch"), "license": (data.get("license") or {}).get("spdx_id"), "private": data.get("private", True)}

    async def discover(self, partition: str = "", cursor: str | None = None, budget: int = 100) -> DiscoveryPage:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            repo = await client.get(f"{API}/repos/{self.owner}/{self.name}", headers=self.headers)
            repo.raise_for_status()
            meta = repo.json()
            if meta.get("private"):
                raise ValueError("只允许接入公开 GitHub 仓库")
            if cursor:
                state = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
                sha = state["sha"]
                pending = state["pending"]
            else:
                branch = meta.get("default_branch") or "main"
                commit = await client.get(f"{API}/repos/{self.owner}/{self.name}/commits/{branch}", headers=self.headers)
                commit.raise_for_status()
                sha = commit.json()["sha"]
                pending = []
                root = await client.get(f"{API}/repos/{self.owner}/{self.name}/git/trees/{sha}", headers=self.headers)
                root.raise_for_status()
                pending = [{"kind": "tree", "sha": root.json()["sha"], "prefix": ""}]
        items: list[SourceRef] = []
        limit = max(1, min(budget, 500))
        license_id = (meta.get("license") or {}).get("spdx_id")
        while pending and len(items) < limit:
            current = pending.pop(0)
            if current["kind"] == "blob":
                path = current["path"]
                items.append(SourceRef(self.key, f"{self.owner}/{self.name}@{sha}:{path}", path,
                                       f"https://github.com/{self.owner}/{self.name}/blob/{sha}/{path}",
                                       {"repo": f"{self.owner}/{self.name}", "path": path, "sha": sha,
                                        "branch": state.get("branch", meta.get("default_branch")) if cursor else meta.get("default_branch"),
                                        "license": license_id, "size": current.get("size"),
                                        "download_url": f"{RAW}/{self.owner}/{self.name}/{sha}/{path}"}))
                continue
            async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
                tree = await client.get(f"{API}/repos/{self.owner}/{self.name}/git/trees/{current['sha']}", headers=self.headers)
                tree.raise_for_status()
                tree_data = tree.json()
            if tree_data.get("truncated"):
                raise RuntimeError(f"GitHub subtree is truncated: {current.get('prefix') or '/'}")
            children = []
            for node in tree_data.get("tree", []):
                path = f"{current['prefix']}{node.get('path', '')}"
                if node.get("type") == "tree":
                    children.append({"kind": "tree", "sha": node["sha"], "prefix": path.rstrip("/") + "/"})
                elif node.get("type") == "blob":
                    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
                    if suffix in MATERIAL_SUFFIXES and int(node.get("size", 0)) <= 2_000_000:
                        children.append({"kind": "blob", "path": path, "size": node.get("size")})
            pending = children + pending
        next_cursor = base64.urlsafe_b64encode(json.dumps({"sha": sha, "pending": pending,
            "branch": meta.get("default_branch")}, separators=(",", ":")).encode()).decode() if pending else None
        return DiscoveryPage(items=items, next_cursor=next_cursor, exhausted=not pending)

    async def fetch(self, ref: SourceRef) -> RawSnapshot:
        url = ref.metadata.get("download_url", "")
        if not url.startswith(RAW + "/"):
            raise ValueError("refuses non-GitHub raw URL")
        return RawSnapshot(ref, stream_http_bytes(url, headers={"User-Agent": "VulnKB/0.1"},
                                                  max_bytes=10 * 1024 * 1024, timeout=30),
                           ref.metadata.get("sha"), ref.metadata.get("license"))


async def search_repositories(query: str, page: int = 1, per_page: int = 100) -> tuple[list[dict], int]:
    """Search only GitHub's public repository index; code search is not assumed available."""
    if not query.strip() or len(query) > 240:
        raise ValueError("query must be 1-240 characters")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
        response = await client.get(f"{API}/search/repositories", params={"q": query, "sort": "updated",
                                                                          "order": "desc", "per_page": min(max(per_page, 1), 100),
                                                                          "page": max(page, 1)}, headers=headers)
        response.raise_for_status()
        data = response.json()
    return data.get("items", []), int(data.get("total_count", 0))

