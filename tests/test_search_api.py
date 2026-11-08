from __future__ import annotations

import asyncio
import secrets
import unittest

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from vuln_kb.database import Base, get_db
from vuln_kb.main import app
from vuln_kb.models import (
    KnowledgeEntry, MaterialVariant, Organization, Product, ProductAlias,
    ProductMaterialApplicability, ProductVulnerability, Session as AuthSession,
    SourceDocument, User,
)


class SearchApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                                    poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        with self.sessions() as db:
            user = User(username="viewer", password_hash="not-used", role="viewer", active=True)
            org = Organization(name="Acme Labs", normalized_name="acme-labs", aliases=[])
            db.add_all([user, org])
            db.flush()
            product = Product(organization_id=org.id, name="Widget", normalized_name="widget", ecosystem="semver",
                              aliases=[], external_ids=[])
            entry = KnowledgeEntry(id="api-entry-1", title="Synthetic approved issue", summary="fixture",
                                   cve_id="CVE-2099-0001", status="published")
            db.add_all([product, entry])
            db.flush()
            db.add(ProductAlias(product_id=product.id, alias="Widget Classic", normalized_alias="widget-classic",
                                evidence_json={"source": "fixture"}))
            db.add(ProductVulnerability(entry_id=entry.id, product_id=product.id,
                                        version_expression=">=1.0.0 <2.0.0", version_status="unknown",
                                        impact="synthetic impact"))
            source = SourceDocument(source_key="fixture", external_id="api-source", url="https://fixture.invalid/doc",
                                    title="Synthetic source")
            db.add(source)
            db.flush()
            material = MaterialVariant(id="api-material-1", entry_id=entry.id, source_document_id=source.id,
                                       material_kind="procedure", language="text", source_url=source.url,
                                       source_revision="r1", sha256="a" * 64,
                                       object_key=f"published/sha256/aa/{'a' * 64}", review_status="approved",
                                       evidence_grade="material_reviewed")
            db.add(material)
            db.flush()
            db.add(ProductMaterialApplicability(material_id=material.id, product_id=product.id,
                                                version_expression=">=1.5.0 <2.0.0",
                                                version_status="unknown", evidence_refs=[]))
            self.user_id, self.product_id, self.entry_id = user.id, product.id, entry.id
            token = secrets.token_urlsafe(32)
            import hashlib
            from datetime import datetime, timedelta, timezone
            db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id,
                               expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
            db.commit()
        self.token = token

        def override_db():
            with self.sessions() as db:
                yield db

        self.override_db = override_db
        app.dependency_overrides[get_db] = override_db

    def tearDown(self) -> None:
        app.dependency_overrides.pop(get_db, None)
        self.engine.dispose()

    async def _request(self, path: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver",
                                     cookies={"vkb_session": self.token}) as client:
            return await client.get(path)

    def test_product_alias_suggestion_and_product_id_disambiguation(self) -> None:
        suggestion = asyncio.run(self._request("/api/suggest?q=Widget%20Classic"))
        self.assertEqual(suggestion.status_code, 200, suggestion.text)
        self.assertEqual(suggestion.json()["items"][0]["id"], self.product_id)
        self.assertEqual(suggestion.json()["items"][0]["matched_alias"], "Widget Classic")
        results = asyncio.run(self._request(f"/api/search?product_id={self.product_id}&version=1.7.0"))
        self.assertEqual(results.status_code, 200, results.text)
        body = results.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["material_count"], 1)
        self.assertEqual(body["items"][0]["evidence_grades"], ["material_reviewed"])
        self.assertEqual(body["items"][0]["products"][0]["evidence_grades"], ["material_reviewed"])
        self.assertEqual(body["items"][0]["products"][0]["version_status"], "affected")
        fuzzy = asyncio.run(self._request("/api/search?product=Widget%20Classic"))
        self.assertEqual(fuzzy.status_code, 200, fuzzy.text)
        self.assertEqual(fuzzy.json()["total"], 1)

    def test_cursor_pagination_keeps_all_results_and_has_independent_count(self) -> None:
        with self.sessions() as db:
            entry = KnowledgeEntry(id="api-entry-2", title="Second synthetic issue", summary="fixture two",
                                   status="published")
            db.add(entry)
            db.flush()
            db.add(ProductVulnerability(entry_id=entry.id, product_id=self.product_id,
                                        version_expression=">=1.0.0 <2.0.0", version_status="unknown"))
            source = SourceDocument(source_key="fixture", external_id="api-source-2",
                                    url="https://fixture.invalid/doc2", title="Synthetic source 2")
            db.add(source)
            db.flush()
            material = MaterialVariant(id="api-material-2", entry_id=entry.id, source_document_id=source.id,
                                       material_kind="procedure", source_url=source.url, sha256="b" * 64,
                                       object_key=f"published/sha256/bb/{'b' * 64}", review_status="approved")
            db.add(material)
            db.flush()
            db.add(ProductMaterialApplicability(material_id=material.id, product_id=self.product_id,
                                                version_expression=">=1.0.0 <2.0.0", version_status="unknown"))
            db.commit()
        first = asyncio.run(self._request(f"/api/search?product_id={self.product_id}&limit=1"))
        self.assertEqual(first.status_code, 200, first.text)
        page1 = first.json()
        self.assertEqual(page1["total"], 2)
        self.assertIsNotNone(page1["next_cursor"])
        second = asyncio.run(self._request(f"/api/search?product_id={self.product_id}&limit=1&cursor={page1['next_cursor']}"))
        self.assertEqual(second.status_code, 200, second.text)
        page2 = second.json()
        self.assertEqual(page2["total"], 2)
        self.assertNotEqual(page1["items"][0]["id"], page2["items"][0]["id"])

    def test_material_scoped_product_list_detail_and_unknown_version(self) -> None:
        materials = asyncio.run(self._request(f"/api/products/{self.product_id}/materials?version=1.2.0"))
        self.assertEqual(materials.status_code, 200, materials.text)
        self.assertEqual(materials.json()["total"], 0)
        detail = asyncio.run(self._request(f"/api/vulnerabilities/{self.entry_id}?product_id={self.product_id}&version=1.7.0"))
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual([item["id"] for item in detail.json()["materials"]], ["api-material-1"])
        unknown = asyncio.run(self._request(f"/api/search?product_id={self.product_id}&version=main"))
        self.assertEqual(unknown.json()["total"], 1)
        self.assertEqual(unknown.json()["items"][0]["products"][0]["version_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
