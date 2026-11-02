from __future__ import annotations

import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vuln_kb.database import Base
from vuln_kb.models import (KnowledgeEntry, MaterialVariant, Organization, Product,
                            ProductMaterialApplicability, ProductVulnerability, SourceDocument)
from vuln_kb.services.search import search_entries


class SearchFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        acme = Organization(name="Acme", normalized_name="acme", aliases=[])
        beta = Organization(name="Beta", normalized_name="beta", aliases=[])
        self.db.add_all([acme, beta])
        self.db.flush()
        p1 = Product(organization_id=acme.id, name="Widget", normalized_name="widget", ecosystem="semver",
                     aliases=["W-1"], external_ids=[])
        p2 = Product(organization_id=beta.id, name="Widget", normalized_name="widget", aliases=[], external_ids=[])
        self.db.add_all([p1, p2])
        self.db.flush()
        published = KnowledgeEntry(id="published-1", title="Synthetic fixture issue", summary="offline sample", status="published")
        hidden = KnowledgeEntry(id="candidate-1", title="Unreviewed fixture issue", summary="must stay hidden", status="candidate")
        self.db.add_all([published, hidden])
        self.db.flush()
        self.db.add_all([
            ProductVulnerability(entry_id=published.id, product_id=p1.id,
                                 version_expression=">=1.0.0 <2.0.0", version_status="unknown"),
            ProductVulnerability(entry_id=published.id, product_id=p2.id, version_status="unknown"),
            ProductVulnerability(entry_id=hidden.id, product_id=p1.id, version_status="unknown"),
        ])
        source = SourceDocument(source_key="fixture", external_id="published-source",
                                url="https://fixture.invalid/source", title="synthetic")
        self.db.add(source)
        self.db.flush()
        material = MaterialVariant(id="published-material", entry_id=published.id, source_document_id=source.id,
                                   material_kind="procedure", source_url=source.url, sha256="a" * 64,
                                   object_key=f"published/sha256/aa/{'a' * 64}", review_status="approved")
        self.db.add(material)
        self.db.flush()
        self.db.add(ProductMaterialApplicability(material_id=material.id, product_id=p1.id,
                                                 version_expression=">=1.4.0 <1.5.0", version_status="unknown"))
        self.db.commit()
        self.acme_product_id = p1.id

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def test_search_disambiguates_same_name_and_hides_candidate_records(self) -> None:
        results, total, _ = search_entries(self.db, product="Widget", product_id=self.acme_product_id)
        self.assertEqual(total, 1)
        self.assertEqual([item[0].id for item in results], ["published-1"])
        self.assertEqual([link.product_id for link in results[0][1]], [self.acme_product_id])

    def test_search_accepts_product_alias(self) -> None:
        results, total, _ = search_entries(self.db, query="W-1", product_id=self.acme_product_id)
        self.assertEqual(total, 1)
        self.assertEqual(results[0][0].id, "published-1")

    def test_semver_range_is_compared_instead_of_substring_matched(self) -> None:
        included, included_total, _ = search_entries(self.db, product_id=self.acme_product_id, version="1.4.9")
        excluded, excluded_total, _ = search_entries(self.db, product_id=self.acme_product_id, version="1.5.0")
        self.assertEqual((included_total, [entry.id for entry, _ in included]), (1, ["published-1"]))
        self.assertEqual((excluded_total, excluded), (0, []))

    def test_material_from_one_product_is_not_returned_for_another_product(self) -> None:
        beta_id = self.db.scalar(select(Product.id).join(Organization).where(Organization.name == "Beta"))
        results, total, _ = search_entries(self.db, product_id=beta_id)
        self.assertEqual(total, 0)
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
