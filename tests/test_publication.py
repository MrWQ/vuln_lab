from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from vuln_kb.database import Base
from vuln_kb.models import (
    KnowledgeEntry, MaterialVariant, Organization, Product,
    ProductMaterialApplicability, ProductVulnerability, PublicationOutbox,
    ReproductionPackage, SourceDocument,
)
from vuln_kb.services.publication import PublicationError, publish_entry, revoke_material
from vuln_kb.storage import ObjectStore


class PublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = ObjectStore(Path(self.temp.name) / "objects")
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        org = Organization(name="Acme", normalized_name="acme", aliases=[])
        self.db.add(org)
        self.db.flush()
        self.product = Product(organization_id=org.id, name="Cache", normalized_name="cache",
                               aliases=[], external_ids=[])
        self.entry = KnowledgeEntry(id="entry-1", title="Synthetic record", summary="summary", status="candidate")
        source = SourceDocument(source_key="fixture", external_id="s1", url="https://fixture.invalid/s1", title="sample")
        self.db.add_all([self.product, self.entry, source])
        self.db.flush()
        self.db.add(ProductVulnerability(entry_id=self.entry.id, product_id=self.product.id,
                                         version_expression="<2.0.0", version_status="unknown"))
        self.source = source
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def add_material(self, material_id: str, content: bytes, *, approved: bool = True) -> MaterialVariant:
        digest, candidate_key = self.store.put(content, namespace="candidate")
        _, published_key, _ = self.store.promote(candidate_key)
        material = MaterialVariant(id=material_id, entry_id=self.entry.id, source_document_id=self.source.id,
                                   material_kind="procedure", source_url=self.source.url,
                                   sha256=digest, object_key=published_key,
                                   review_status="approved" if approved else "pending",
                                   evidence_grade="material_reviewed",
                                   gates={key: "pass" for key in ("G1_source", "G2_material", "G3_prerequisites",
                                                                    "G4_success_impact", "G5_usable")})
        self.db.add(material)
        self.db.flush()
        self.db.add(ReproductionPackage(material_id=material.id, prerequisites="local fixture",
                                        instructions="steps for local fixture", success_criteria="fixture marker"))
        self.db.add(ProductMaterialApplicability(material_id=material.id, product_id=self.product.id,
                                                 version_status="unknown", evidence_refs=[]))
        self.db.flush()
        return material

    def test_publish_requires_complete_approved_material_and_emits_outbox_atomically(self) -> None:
        with self.assertRaises(PublicationError):
            publish_entry(self.db, self.entry, self.store)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(PublicationOutbox)), 0)
        material = self.add_material("m1", b"synthetic reproduction")
        event = publish_entry(self.db, self.entry, self.store)
        self.assertEqual(self.entry.status, "published")
        self.assertEqual(event.publication_revision, 1)
        self.assertEqual(material.gates["G6_review_complete"], "pass")
        self.db.commit()
        same = publish_entry(self.db, self.entry, self.store)
        self.assertEqual(same.id, event.id)
        self.assertEqual(self.db.scalar(select(func.count()).select_from(PublicationOutbox)), 1)

    def test_publication_state_and_outbox_rollback_together(self) -> None:
        self.add_material("m1", b"rollback sample")
        publish_entry(self.db, self.entry, self.store)
        self.db.rollback()
        self.db.expire_all()
        self.assertEqual(self.db.get(KnowledgeEntry, "entry-1").status, "candidate")
        self.assertEqual(self.db.scalar(select(func.count()).select_from(PublicationOutbox)), 0)

    def test_pending_implementation_does_not_down_publish_and_new_approved_material_revisions_outbox(self) -> None:
        first = self.add_material("m1", b"first material")
        event1 = publish_entry(self.db, self.entry, self.store)
        self.db.commit()
        pending = self.add_material("m2", b"pending material", approved=False)
        self.assertEqual(self.entry.status, "published")
        self.db.delete(pending)
        self.db.flush()
        second = self.add_material("m2", b"second approved")
        event2 = publish_entry(self.db, self.entry, self.store)
        self.assertEqual(event2.publication_revision, event1.publication_revision + 1)
        self.assertEqual(first.review_status, "approved")
        self.assertEqual(second.review_status, "approved")

    def test_revoking_one_of_multiple_materials_keeps_entry_available_but_last_revocation_hides_it(self) -> None:
        first = self.add_material("m1", b"first")
        second = self.add_material("m2", b"second")
        publish_entry(self.db, self.entry, self.store)
        self.db.commit()
        remains = revoke_material(self.db, first, "fixture invalidation")
        self.assertTrue(remains)
        self.assertEqual(self.entry.status, "published")
        remains = revoke_material(self.db, second, "final material invalidation")
        self.assertFalse(remains)
        self.assertEqual(self.entry.status, "needs_revalidation")
        self.assertGreaterEqual(self.db.scalar(select(func.count()).select_from(PublicationOutbox)), 3)


if __name__ == "__main__":
    unittest.main()
