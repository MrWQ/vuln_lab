from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import HTTPException, Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vuln_kb.database import Base, get_db
from vuln_kb import main
from vuln_kb.exports import _md, _md_url
from vuln_kb.models import (
    AIProviderConfig, KnowledgeEntry, MaterialVariant, Organization, Product,
    ProductMaterialApplicability, ProductVulnerability, Session as AuthSession,
    SourceDocument, User,
)
from vuln_kb.security import create_session, current_user, hash_password, verify_password
from vuln_kb.storage import ObjectStore


class AccessSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = ObjectStore(Path(self.temp.name) / "objects")
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                                    poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.tokens: dict[str, str] = {}
        with self.sessions() as db:
            users = [User(username=role, password_hash="unused", role=role, active=True)
                     for role in ("viewer", "editor", "admin")]
            org = Organization(name="Acme", normalized_name="acme", aliases=[])
            db.add_all([*users, org])
            db.flush()
            product = Product(organization_id=org.id, name="Widget", normalized_name="widget", ecosystem="semver",
                              aliases=[], external_ids=[])
            candidate = KnowledgeEntry(id="candidate-security", title="<script>candidate()</script>",
                                       summary="pending", status="candidate")
            published = KnowledgeEntry(id="published-security", title="<script>alert(1)</script>",
                                        summary="<img src=x onerror=alert(1)>", status="published")
            db.add_all([product, candidate, published])
            db.flush()
            db.add(ProductVulnerability(entry_id=published.id, product_id=product.id,
                                        version_expression="<2.0.0", version_status="unknown"))
            source = SourceDocument(source_key="fixture", external_id="security-source",
                                    url="javascript:alert(1)", title="<svg onload=alert(1)>")
            db.add(source)
            db.flush()
            content = b"safe synthetic attachment"
            digest, candidate_key = self.store.put(content)
            _, published_key, _ = self.store.promote(candidate_key)
            material = MaterialVariant(id="material-security", entry_id=published.id, source_document_id=source.id,
                                       material_kind="procedure", source_url="javascript:alert(1)", sha256=digest,
                                       object_key=published_key, review_status="approved",
                                       evidence_grade="material_reviewed")
            db.add(material)
            db.flush()
            db.add(ProductMaterialApplicability(material_id=material.id, product_id=product.id,
                                                version_status="unknown", evidence_refs=[]))
            for user in users:
                token = secrets.token_urlsafe(32)
                self.tokens[user.role] = token
                db.add(AuthSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id,
                                   expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
            db.add(AIProviderConfig(name="default", base_url="https://model.invalid/v1", model="fixture",
                                    api_key_ciphertext="secret-ciphertext-sentinel", enabled=False))
            self.product_id = product.id
            db.commit()

        def override_db():
            with self.sessions() as db:
                yield db

        self.override_db = override_db
        main.app.dependency_overrides[get_db] = override_db
        self.original_store = main.ObjectStore
        main.ObjectStore = lambda: self.store

    def tearDown(self) -> None:
        main.app.dependency_overrides.pop(get_db, None)
        main.ObjectStore = self.original_store
        self.engine.dispose()
        self.temp.cleanup()

    async def _request(self, role: str, method: str, path: str, *, body=None, csrf: bool = False):
        headers = {}
        cookies = {"vkb_session": self.tokens[role]}
        if csrf:
            cookies["vkb_csrf"] = "csrf-token"
            headers["X-CSRF-Token"] = "csrf-token"
        transport = httpx.ASGITransport(app=main.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver",
                                     cookies=cookies, headers=headers) as client:
            return await client.request(method, path, json=body)

    def test_viewer_sees_only_published_content_and_can_download_approved_material(self) -> None:
        hidden = asyncio.run(self._request("viewer", "GET", "/api/vulnerabilities/candidate-security"))
        self.assertEqual(hidden.status_code, 404)
        candidate_download = asyncio.run(self._request("viewer", "GET", "/materials/not-a-material/download"))
        self.assertEqual(candidate_download.status_code, 404)
        downloaded = asyncio.run(self._request("viewer", "GET", "/materials/material-security/download"))
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.content, b"safe synthetic attachment")
        self.assertEqual(downloaded.headers["x-content-type-options"], "nosniff")
        self.assertIn("attachment;", downloaded.headers["content-disposition"])

    def test_search_workbench_exposes_accessible_product_filters_and_result_states(self) -> None:
        response = asyncio.run(self._request("viewer", "GET", "/"))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('role="combobox"', response.text)
        self.assertIn('role="listbox"', response.text)
        self.assertIn('id="active-filters"', response.text)
        self.assertIn("漏洞数按唯一记录统计", response.text)
        script = (main.ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("new AbortController()", script)
        self.assertIn("compositionend", script)
        self.assertIn("window.addEventListener('popstate'", script)

    def test_roles_and_csrf_protect_write_and_admin_pages(self) -> None:
        viewer_admin = asyncio.run(self._request("viewer", "GET", "/admin"))
        self.assertEqual(viewer_admin.status_code, 403)
        editor_create = asyncio.run(self._request("editor", "POST", "/api/admin/users", body={
            "username": "new-viewer", "password": "long-password-123", "role": "viewer"}, csrf=True))
        self.assertEqual(editor_create.status_code, 403)
        editor_without_csrf = asyncio.run(self._request("editor", "POST", "/api/admin/jobs", body={
            "source": "github_repo", "repo": "example/project", "budget": 1}))
        self.assertEqual(editor_without_csrf.status_code, 403)
        editor_with_csrf = asyncio.run(self._request("editor", "POST", "/api/admin/jobs", body={
            "source": "github_repo", "repo": "example/project", "budget": 1}, csrf=True))
        self.assertEqual(editor_with_csrf.status_code, 200, editor_with_csrf.text)
        editor_admin = asyncio.run(self._request("editor", "GET", "/admin"))
        self.assertEqual(editor_admin.status_code, 200, editor_admin.text)
        self.assertNotIn("secret-ciphertext-sentinel", editor_admin.text)
        admin_create = asyncio.run(self._request("admin", "POST", "/api/admin/users", body={
            "username": "new-viewer", "password": "long-password-123", "role": "viewer"}, csrf=True))
        self.assertEqual(admin_create.status_code, 200, admin_create.text)
        self.assertEqual(admin_create.json()["role"], "viewer")

    def test_revoked_last_material_stops_download_and_external_content_is_escaped(self) -> None:
        page = asyncio.run(self._request("viewer", "GET", "/v/published-security"))
        self.assertEqual(page.status_code, 200, page.text)
        self.assertNotIn("<script>alert(1)</script>", page.text)
        self.assertNotIn("<img src=x onerror=alert(1)>", page.text)
        self.assertNotIn('href="javascript:alert(1)"', page.text)
        self.assertIn("来源链接不可用", page.text)

        response = asyncio.run(self._request("editor", "POST", "/api/admin/materials/material-security/revoke",
                                             body={"reason": "fixture invalidation"}, csrf=True))
        self.assertEqual(response.status_code, 200, response.text)
        download = asyncio.run(self._request("viewer", "GET", "/materials/material-security/download"))
        self.assertEqual(download.status_code, 404)

    def test_markdown_export_escapes_markup_and_rejects_active_schemes(self) -> None:
        self.assertNotIn("<script>", _md("<script>alert(1)</script>"))
        self.assertEqual(_md_url("javascript:alert(1)"), "")
        self.assertTrue(_md_url("https://example.invalid/report").startswith("https://"))

    def test_password_hashing_and_session_expiry(self) -> None:
        encoded = hash_password("correct horse battery staple")
        self.assertNotEqual(encoded, "correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", encoded))
        self.assertFalse(verify_password("wrong password", encoded))
        with self.sessions() as db:
            user = User(username="session-user", password_hash=encoded, role="viewer", active=True)
            db.add(user)
            db.commit()
            db.refresh(user)
            token = create_session(db, user)
            request = Request({"type": "http", "headers": [(b"cookie", f"vkb_session={token}".encode())],
                               "method": "GET", "path": "/", "query_string": b"",
                               "server": ("testserver", 80), "client": ("testclient", 50000),
                               "scheme": "http", "root_path": "", "http_version": "1.1"})
            self.assertEqual(current_user(request, db).username, "session-user")
            session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
            session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
            with self.assertRaises(HTTPException) as expired:
                current_user(request, db)
            self.assertEqual(expired.exception.status_code, 401)

    def test_login_csrf_form_creates_authenticated_session(self) -> None:
        with self.sessions() as db:
            db.add(User(username="login-user", password_hash=hash_password("login-password-123"),
                        role="viewer", active=True))
            db.commit()

        async def login_flow():
            transport = httpx.ASGITransport(app=main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                page = await client.get("/login")
                token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
                denied = await client.post("/login", data={"username": "login-user",
                    "password": "login-password-123", "csrf_token": "wrong"}, follow_redirects=False)
                self.assertEqual(denied.status_code, 403)
                response = await client.post("/login", data={"username": "login-user",
                    "password": "login-password-123", "csrf_token": token}, follow_redirects=False)
                return response, client.cookies

        response, cookies = asyncio.run(login_flow())
        self.assertEqual(response.status_code, 303)
        self.assertIn("vkb_session", cookies)
        self.assertTrue(cookies["vkb_session"])
        self.assertIn("vkb_csrf", cookies)


if __name__ == "__main__":
    unittest.main()
