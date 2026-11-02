from __future__ import annotations

from importlib.metadata import entry_points

from vuln_kb.adapters.exploitdb import ExploitDBAdapter
from vuln_kb.adapters.github import GitHubAdapter
from vuln_kb.adapters.mapped_feed import MappedFeedAdapter, load_mapped_sources
from vuln_kb.config import settings


def registered_source_keys() -> set[str]:
    keys = {"github_repo", "exploitdb", *load_mapped_sources(settings.sources_config).keys()}
    for point in entry_points(group="vuln_kb.adapters"):
        keys.add(point.name)
    return keys


def create_adapter(source_key: str, repo: str | None = None):
    if source_key == "github_repo":
        return GitHubAdapter(repo or "")
    if source_key == "exploitdb":
        return ExploitDBAdapter()
    mapped = load_mapped_sources(settings.sources_config).get(source_key)
    if mapped:
        return MappedFeedAdapter(mapped)
    for point in entry_points(group="vuln_kb.adapters"):
        if point.name == source_key:
            factory = point.load()
            adapter = factory(repo=repo) if repo else factory()
            if getattr(adapter, "key", None) != source_key:
                raise ValueError("plugin adapter key does not match its registered entry point")
            return adapter
    raise ValueError(f"unknown source adapter: {source_key}")

