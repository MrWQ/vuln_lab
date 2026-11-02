"""Version range matching for explicitly supported package ecosystems.

Unknown ecosystems and expressions deliberately produce ``unknown``. The caller
must preserve the original range and must not interpret unknown as safe.
"""
from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


_SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_TOKEN = re.compile(r"(\^|~|>=|<=|==|>|<|=)?\s*(v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)")


def _semver_version(value: str) -> tuple | None:
    value = value.strip()
    match = _SEMVER.fullmatch(value)
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    identifiers = []
    if prerelease:
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    return None
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
    # SemVer ignores build metadata and orders a release after its prereleases.
    return int(major), int(minor), int(patch), 1 if prerelease is None else 0, tuple(identifiers)


def _semver_clause(value: str) -> list[tuple[str, tuple]] | None:
    value = value.strip()
    if not value:
        return None
    hyphen = re.fullmatch(r"\s*(v?\d+\.\d+\.\d+)\s+-\s+(v?\d+\.\d+\.\d+)\s*", value)
    if hyphen:
        low, high = (_semver_version(v) for v in hyphen.groups())
        return [(">=", low), ("<=", high)] if low is not None and high is not None else None

    normalized = value.replace(",", " ")
    tokens = list(_TOKEN.finditer(normalized))
    if not tokens or "".join(m.group(0) for m in tokens).replace(" ", "") != normalized.replace(" ", ""):
        return None
    result: list[tuple[str, Version]] = []
    for match in tokens:
        operator, raw = match.groups()
        operator = operator or "="
        parsed = _semver_version(raw)
        if parsed is None:
            return None
        if operator in {"^", "~"}:
            result.append((">=", parsed))
            major, minor, patch = (int(part) for part in raw.lstrip("v").split("-", 1)[0].split("."))
            if operator == "~":
                upper = f"{major}.{minor + 1}.0"
            elif major:
                upper = f"{major + 1}.0.0"
            elif minor:
                upper = f"0.{minor + 1}.0"
            else:
                upper = f"0.0.{patch + 1}"
            upper_version = _semver_version(upper)
            if upper_version is None:
                return None
            result.append(("<", upper_version))
        else:
            result.append(({"=": "=="}.get(operator, operator), parsed))
    return result


def _matches_semver(version: str, expression: str) -> bool | None:
    candidate = _semver_version(version)
    if candidate is None:
        return None
    alternatives = expression.split("||")
    for alternative in alternatives:
        clause = _semver_clause(alternative)
        if clause is None:
            return None
        matches = True
        for operator, bound in clause:
            if operator not in {"==", ">=", "<=", ">", "<"}:
                return None
            matches &= {"==": candidate == bound, ">=": candidate >= bound, "<=": candidate <= bound,
                        ">": candidate > bound, "<": candidate < bound}[operator]
        if matches:
            return True
    return False


def match_version(ecosystem: str | None, version: str | None, expression: str | None) -> str:
    """Return affected, not_affected, or unknown using an ecosystem comparator."""
    if not ecosystem or not version or not expression:
        return "unknown"
    ecosystem = ecosystem.strip().lower()
    if ecosystem in {"semver", "npm", "node", "nodejs"}:
        matched = _matches_semver(version, expression)
    elif ecosystem in {"pypi", "python"}:
        try:
            candidate = Version(version.strip())
            specifiers = expression.strip()
            if not re.search(r"(?:===|==|!=|~=|<=|>=|<|>)", specifiers):
                specifiers = f"=={specifiers}"
            matched = candidate in SpecifierSet(specifiers, prereleases=True)
        except (InvalidVersion, InvalidSpecifier, ValueError):
            matched = None
    else:
        matched = None
    return "unknown" if matched is None else "affected" if matched else "not_affected"
