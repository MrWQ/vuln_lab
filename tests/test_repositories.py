from __future__ import annotations

import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from vuln_kb.database import Base
from vuln_kb.models import (KnowledgeEntry, ProductAlias, ProductMaterialApplicability,
                            ProductVulnerability, SourceDocument, SourceRevision)
from vuln_kb.repositories import (
    get_or_create_organization, get_or_create_product, link_material_to_product,
    upsert_product_vulnerability, upsert_source,
)


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def test_source_and_revision_upserts_are_idempotent(self) -> None:
        args = dict(source_key="fixture", external_id="doc-1", url="https://fixture.invalid/doc-1",
                    title="Synthetic doc", revision="rev-1", sha256="a" * 64,
                    object_key=f"sha256/aa/{'a' * 64}", size_bytes=20, metadata={"path": "README.md"})
        first, revision1, created = upsert_source(self.db, **args)
        second, revision2, created_again = upsert_source(self.db, **args)
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first.id, second.id)
        self.assertEqual(revision1.id, revision2.id)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(SourceDocument)), 1)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(SourceRevision)), 1)

    def test_same_product_name_under_distinct_organizations_remains_distinct(self) -> None:
        acme, _ = get_or_create_organization(self.db, "Acme")
        beta, _ = get_or_create_organization(self.db, "Beta")
        first, made = get_or_create_product(self.db, "Widget", organization_id=acme.id, aliases=["Common Widget"])
        same, made_again = get_or_create_product(self.db, "Widget", organization_id=acme.id, aliases=["Common Widget"])
        second, _ = get_or_create_product(self.db, "Widget", organization_id=beta.id, aliases=["Common Widget"])
        self.assertTrue(made)
        self.assertFalse(made_again)
        self.assertEqual(first.id, same.id)
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(ProductAlias)), 2)

    def test_product_identifiers_are_idempotent_and_conflicts_are_rejected(self) -> None:
        acme, _ = get_or_create_organization(self.db, "Acme")
        beta, _ = get_or_create_organization(self.db, "Beta")
        product, _ = get_or_create_product(self.db, "Cache", organization_id=acme.id,
                                           identifiers={"purl": "pkg:npm/acme/cache"})
        again, created = get_or_create_product(self.db, "Cache", organization_id=acme.id,
                                               identifiers={"purl": "pkg:npm/acme/cache"})
        self.assertEqual(product.id, again.id)
        self.assertFalse(created)
        with self.assertRaises(ValueError):
            get_or_create_product(self.db, "Cache", organization_id=beta.id,
                                  identifiers={"purl": "pkg:npm/acme/cache"})

    def test_entry_supports_multiple_products_and_multiple_material_applicabilities(self) -> None:
        org, _ = get_or_create_organization(self.db, "Acme")
        p1, _ = get_or_create_product(self.db, "Cache A", organization_id=org.id)
        p2, _ = get_or_create_product(self.db, "Cache B", organization_id=org.id)
        entry = KnowledgeEntry(id="fixture-entry", title="Synthetic", status="candidate")
        self.db.add(entry)
        self.db.flush()
        _, created1 = upsert_product_vulnerability(self.db, entry, p1)
        _, created2 = upsert_product_vulnerability(self.db, entry, p2)
        material1, material2 = self._material(p1.id), self._material(p2.id)
        self.db.add_all([material1, material2])
        self.db.flush()
        _, linked1 = link_material_to_product(self.db, material1, p1, version_expression=">=1.0.0")
        _, linked1_again = link_material_to_product(self.db, material1, p1, version_expression=">=1.0.0")
        _, linked2 = link_material_to_product(self.db, material2, p2)
        self.db.commit()
        self.assertTrue(created1 and created2 and linked1 and linked2)
        self.assertFalse(linked1_again)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(ProductVulnerability)), 2)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(ProductMaterialApplicability)), 2)

    def _material(self, product_id: int):
        from vuln_kb.models import MaterialVariant
        source, _, _ = upsert_source(self.db, source_key="fixture", external_id=f"m-{product_id}",
                                     url=f"https://fixture.invalid/{product_id}", title="Synthetic")
        digest = f"{product_id:064x}"
        return MaterialVariant(id=f"material-{product_id}", entry_id="fixture-entry", source_document_id=source.id,
                               material_kind="procedure", source_url=source.url, sha256=digest,
                               object_key=f"sha256/{digest[:2]}/{digest}")


if __name__ == "__main__":
    unittest.main()
