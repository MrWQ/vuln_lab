from __future__ import annotations

import unittest

from vuln_kb.services.versions import match_version


class VersionComparatorTests(unittest.TestCase):
    def test_semver_inclusive_exclusive_and_or_ranges(self) -> None:
        self.assertEqual(match_version("semver", "1.2.0", ">=1.2.0 <2.0.0"), "affected")
        self.assertEqual(match_version("semver", "2.0.0", ">=1.2.0 <2.0.0"), "not_affected")
        self.assertEqual(match_version("semver", "3.2.1", "<2.0.0 || >=3.0.0"), "affected")
        self.assertEqual(match_version("semver", "1.2.0", "1.2.0 - 2.0.0"), "affected")
        self.assertEqual(match_version("semver", "2.0.0", "1.2.0 - 2.0.0"), "affected")

    def test_semver_caret_tilde_and_prerelease_order(self) -> None:
        self.assertEqual(match_version("npm", "0.2.9", "^0.2.3"), "affected")
        self.assertEqual(match_version("npm", "0.3.0", "^0.2.3"), "not_affected")
        self.assertEqual(match_version("semver", "1.4.9", "~1.4.2"), "affected")
        self.assertEqual(match_version("semver", "1.5.0", "~1.4.2"), "not_affected")
        self.assertEqual(match_version("semver", "1.0.0-beta.2", ">=1.0.0-beta.1 <1.0.0"), "affected")
        self.assertEqual(match_version("semver", "1.0.0", ">=1.0.0-beta.1 <1.0.0"), "not_affected")

    def test_pypi_pep440_and_unknown_ecosystem_are_explicit(self) -> None:
        self.assertEqual(match_version("pypi", "2.1rc1", ">=2.0,<2.2"), "affected")
        self.assertEqual(match_version("pypi", "2.2", ">=2.0,<2.2"), "not_affected")
        self.assertEqual(match_version("maven", "1.2.3", ">=1.0.0"), "unknown")
        self.assertEqual(match_version("semver", "main", ">=1.0.0"), "unknown")
        self.assertEqual(match_version("semver", "1.0.0", "vendor-specific"), "unknown")


if __name__ == "__main__":
    unittest.main()
