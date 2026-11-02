from __future__ import annotations

import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
import httpx
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import String, func, or_, select
from sqlalchemy.orm import Session as DBSession, joinedload

from vuln_kb.adapters.exploitdb import ExploitDBAdapter
from vuln_kb.adapters.github import GitHubAdapter
from vuln_kb.adapters.registry import registered_source_keys
from vuln_kb.config import settings
from vuln_kb.database import Base, SessionLocal, engine, ensure_database_parent, get_db
from vuln_kb.exports import publish_export
from vuln_kb.models import (AIProviderConfig, CoveragePartition, Job, KnowledgeEntry, MaterialVariant,
                            Organization, OrganizationAlias, Product, ProductAlias, ProductIdentifier,
                            ProductMaterialApplicability, ProductVulnerability, Session, User)
from vuln_kb.security import (create_session, current_user, encrypt_secret, hash_password,
                              require_roles, verify_password)
from vuln_kb.storage import ObjectStore
from vuln_kb.services.publication import PublicationError, publish_entry, revoke_material
from vuln_kb.services.versions import match_version
from vuln_kb.worker import enqueue

ROOT = Path(__file__).resolve().parents[2]
templates = Jinja2Templates(directory=str(ROOT / "templates"))


def safe_external_url(value: str | None) -> str:
    parsed = urlparse(value or "")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return value or ""


templates.env.filters["safe_external_url"] = safe_external_url


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.app_env.lower() != "development" and (len(settings.secret_key) < 32 or settings.secret_key in {
            "development-only-change-me", "replace-with-a-long-random-secret"}):
        raise RuntimeError("SECRET_KEY must be changed outside development")
    if settings.app_env.lower() != "development" and settings.bootstrap_admin_password == "change-me-before-sharing":
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must be changed before shared deployment")
    ensure_database_parent()
    settings.object_store_dir.mkdir(parents=True, exist_ok=True)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    if settings.bootstrap_admin_password:
        with SessionLocal() as db:
            admin = db.scalar(select(User).where(User.username == settings.bootstrap_admin_username))
            if admin is None:
                db.add(User(username=settings.bootstrap_admin_username,
                            password_hash=hash_password(settings.bootstrap_admin_password), role="admin"))
                db.commit()
    yield


app = FastAPI(title="Vuln KB", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
                                "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
    return response


def csrf_check(request: Request) -> None:
    cookie = request.cookies.get("vkb_csrf", "")
    supplied = request.headers.get("x-csrf-token", "")
    if not cookie or not supplied or not secrets.compare_digest(cookie, supplied):
        raise HTTPException(status_code=403, detail="CSRF token 无效")


def page_context(request: Request, **kwargs):
    return {"request": request, "user": None, **kwargs}


def optional_user(request: Request, db: DBSession = Depends(get_db)) -> User | None:
    try:
        return current_user(request, db)
    except HTTPException:
        return None


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "vuln-kb"}


@app.get("/readyz")
def readyz(db: DBSession = Depends(get_db)):
    try:
        db.execute(select(1))
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready", "database": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    token = secrets.token_urlsafe(24)
    response = templates.TemplateResponse(request=request, name="login.html",
                                          context=page_context(request, error=request.query_params.get("error"), csrf_token=token))
    response.set_cookie("vkb_login_csrf", token, httponly=False, secure=settings.app_env != "development",
                        samesite="strict", max_age=900, path="/")
    return response


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          csrf_token: str = Form(...), db: DBSession = Depends(get_db)):
    cookie_token = request.cookies.get("vkb_login_csrf", "")
    if not cookie_token or not secrets.compare_digest(cookie_token, csrf_token):
        raise HTTPException(status_code=403, detail="登录表单已过期，请刷新后重试")
    user = db.scalar(select(User).where(User.username == username, User.active.is_(True)))
    if not user or not verify_password(password, user.password_hash):
        return RedirectResponse("/login?error=1", status_code=303)
    token = create_session(db, user)
    csrf = secrets.token_urlsafe(24)
    redirect = RedirectResponse("/", status_code=303)
    redirect.set_cookie("vkb_session", token, httponly=True, secure=settings.app_env != "development",
                        samesite="lax", max_age=settings.session_hours * 3600, path="/")
    redirect.set_cookie("vkb_csrf", csrf, httponly=False, secure=settings.app_env != "development",
                        samesite="strict", max_age=settings.session_hours * 3600, path="/")
    redirect.delete_cookie("vkb_login_csrf", path="/")
    return redirect


@app.post("/logout")
def logout(request: Request, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    csrf_check(request)
    token = request.cookies.get("vkb_session", "")
    from vuln_kb.models import Session as AuthSession
    db.delete(db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest()))
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("vkb_session", path="/")
    response.delete_cookie("vkb_csrf", path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request, user: User | None = Depends(optional_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    response = templates.TemplateResponse(request=request, name="search.html", context=page_context(request, user=user))
    return response


def _applicable_materials(db: DBSession, entry_id: str, product_id: int,
                          requested_version: str = "") -> list[MaterialVariant]:
    rows = db.execute(select(MaterialVariant, ProductMaterialApplicability.version_expression, Product.ecosystem)
                      .join(ProductMaterialApplicability,
                            ProductMaterialApplicability.material_id == MaterialVariant.id)
                      .join(Product, Product.id == ProductMaterialApplicability.product_id)
                      .where(MaterialVariant.entry_id == entry_id,
                             MaterialVariant.review_status == "approved",
                             ProductMaterialApplicability.product_id == product_id)).all()
    if not requested_version:
        return [material for material, _, _ in rows]
    vulnerability = db.scalar(select(ProductVulnerability).where(
        ProductVulnerability.entry_id == entry_id, ProductVulnerability.product_id == product_id))
    vuln_range = vulnerability.version_expression if vulnerability else None
    result = []
    for material, material_range, ecosystem in rows:
        vuln_status = match_version(ecosystem, requested_version, vuln_range)
        material_status = match_version(ecosystem, requested_version, material_range)
        if vuln_status != "not_affected" and material_status != "not_affected":
            result.append(material)
    return result


@app.get("/api/search")
def api_search(q: str = "", company: str = "", product: str = "", version: str = "",
               limit: int = 50, cursor: str | None = None, product_id: int | None = None,
               db: DBSession = Depends(get_db), user: User = Depends(current_user)):
    from vuln_kb.services.search import search_entries
    limit = max(1, min(limit, 100))
    try:
        rows, count, next_cursor = search_entries(db, q, company, product, version, limit, cursor, product_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    entry_ids = [entry.id for entry, _ in rows]
    out = []
    for entry, relations in rows:
        products = []
        entry_material_ids: set[str] = set()
        for relation in relations:
            product_obj = relation.product
            org = product_obj.organization.name if product_obj.organization else "未知厂商"
            materials = _applicable_materials(db, entry.id, relation.product_id, version)
            entry_material_ids.update(material.id for material in materials)
            version_status = relation.version_status
            if version:
                vuln_status = match_version(product_obj.ecosystem, version, relation.version_expression)
                material_statuses = [match_version(product_obj.ecosystem, version, item.version_expression)
                                     for item in db.scalars(select(ProductMaterialApplicability).where(
                                         ProductMaterialApplicability.product_id == relation.product_id,
                                         ProductMaterialApplicability.material_id.in_([m.id for m in materials]))).all()]
                version_status = "affected" if vuln_status == "affected" and material_statuses and all(
                    status == "affected" for status in material_statuses) else "unknown"
            products.append({"company": org, "product": product_obj.name,
                             "product_id": relation.product_id, "version": relation.version_expression,
                             "version_status": version_status, "impact": relation.impact,
                             "match_confidence": relation.match_confidence, "material_count": len(materials)})
        primary = products[0] if products else {"company": "未知厂商", "product": "未知产品",
                                                 "version": None, "version_status": "unknown",
                                                 "impact": "", "match_confidence": 0}
        out.append({"id": entry.id, "title": entry.title, "summary": entry.summary, "cve_id": entry.cve_id,
                    "vuln_type": entry.vuln_type, **primary, "products": products,
                    "material_count": len(entry_material_ids), "url": f"/v/{entry.id}"})
    return {"items": out, "total": count, "limit": limit, "next_cursor": next_cursor}


@app.get("/api/coverage")
def api_coverage(db: DBSession = Depends(get_db), user: User = Depends(current_user)):
    partitions = db.scalars(select(CoveragePartition).order_by(CoveragePartition.source_key,
                                                               CoveragePartition.partition_key)).all()
    job_rows = db.execute(select(Job.state, Job.kind, func.count()).group_by(Job.state, Job.kind)).all()
    jobs_by_state: dict[str, int] = {}
    jobs_by_kind: dict[str, dict[str, int]] = {}
    for state, kind, count in job_rows:
        jobs_by_state[state] = jobs_by_state.get(state, 0) + count
        jobs_by_kind.setdefault(kind, {})[state] = count
    return {"published_vulnerabilities": db.scalar(select(func.count()).select_from(KnowledgeEntry).where(KnowledgeEntry.status == "published")) or 0,
            "published_product_links": db.scalar(select(func.count()).select_from(ProductVulnerability).join(KnowledgeEntry).where(KnowledgeEntry.status == "published")) or 0,
            "published_products": db.scalar(select(func.count(func.distinct(ProductVulnerability.product_id)))
                                             .select_from(ProductVulnerability).join(KnowledgeEntry)
                                             .where(KnowledgeEntry.status == "published")) or 0,
            "approved_materials": db.scalar(select(func.count()).select_from(MaterialVariant).join(KnowledgeEntry).where(
                KnowledgeEntry.status == "published", MaterialVariant.review_status == "approved")) or 0,
            "jobs_by_state": jobs_by_state, "jobs_by_kind": jobs_by_kind,
            "sources": [{"source": p.source_key, "partition": p.partition_key, "state": p.state,
                         "discovered": p.discovered_refs, "processed": p.processed_refs,
                         "last_sync_at": p.last_sync_at.isoformat() if p.last_sync_at else None,
                         "error": p.last_error} for p in partitions]}


@app.get("/api/suggest")
def suggest(q: str = "", db: DBSession = Depends(get_db), user: User = Depends(current_user)):
    needle = q.strip()
    if len(needle) < 2:
        return {"items": []}
    pattern = f"%{needle}%"
    products = db.scalars(select(Product).where(or_(Product.name.ilike(pattern),
                                                     Product.normalized_name.ilike(pattern),
                                                     Product.aliases.cast(String).ilike(pattern),
                                                     select(ProductAlias.id).where(ProductAlias.product_id == Product.id,
                                                                                    ProductAlias.alias.ilike(pattern)).exists(),
                                                     select(ProductIdentifier.id).where(ProductIdentifier.product_id == Product.id,
                                                                                         ProductIdentifier.value.ilike(pattern)).exists()))
                          .options(joinedload(Product.organization)).order_by(Product.name, Product.id).limit(12)).unique().all()
    items = []
    for p in products:
        alias = next((row.alias for row in p.alias_rows if needle.casefold() in row.alias.casefold()), None)
        alias = alias or next((item for item in p.aliases or [] if needle.casefold() in str(item).casefold()), None)
        identifier = db.scalar(select(ProductIdentifier.value).where(ProductIdentifier.product_id == p.id,
                                                                      ProductIdentifier.value.ilike(pattern)).limit(1))
        items.append({"id": p.id, "name": p.name, "company": p.organization.name if p.organization else "",
                      "matched_alias": alias or identifier})
    return {"items": items}


@app.get("/api/products/{product_id}/vulnerabilities")
def product_vulnerabilities(product_id: int, q: str = "", version: str = "", limit: int = 50,
                            cursor: str | None = None, db: DBSession = Depends(get_db),
                            user: User = Depends(current_user)):
    product_obj = db.get(Product, product_id)
    if product_obj is None:
        raise HTTPException(status_code=404, detail="产品不存在")
    from vuln_kb.services.search import search_entries
    try:
        rows, total, next_cursor = search_entries(db, query=q, version=version, limit=limit,
                                                  cursor=cursor, product_id=product_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    items = []
    for entry, relations in rows:
        relation = next((item for item in relations if item.product_id == product_id), None)
        if relation is None:
            continue
        items.append({"id": entry.id, "title": entry.title, "summary": entry.summary,
                      "cve_id": entry.cve_id, "vuln_type": entry.vuln_type,
                      "version": relation.version_expression, "version_status": relation.version_status,
                      "impact": relation.impact,
                      "materials": [{"id": material.id, "kind": material.material_kind,
                                     "evidence_grade": material.evidence_grade,
                                     "download_url": f"/materials/{material.id}/download"}
                                    for material in _applicable_materials(db, entry.id, product_id, version)],
                      "url": f"/v/{entry.id}"})
    return {"product": {"id": product_obj.id, "name": product_obj.name,
                        "company": product_obj.organization.name if product_obj.organization else "未知厂商"},
            "items": items, "total": total, "limit": max(1, min(limit, 100)), "next_cursor": next_cursor}


@app.get("/api/products/{product_id}/materials")
def product_materials(product_id: int, version: str = "", db: DBSession = Depends(get_db),
                      user: User = Depends(current_user)):
    product = db.get(Product, product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="产品不存在")
    entries = db.scalars(select(KnowledgeEntry).join(ProductVulnerability).where(
        ProductVulnerability.product_id == product_id, KnowledgeEntry.status == "published").distinct()).all()
    items = []
    for entry in entries:
        for material in _applicable_materials(db, entry.id, product_id, version):
            link = db.scalar(select(ProductMaterialApplicability).where(
                ProductMaterialApplicability.material_id == material.id,
                ProductMaterialApplicability.product_id == product_id))
            items.append({"id": material.id, "entry_id": entry.id, "title": entry.title,
                          "kind": material.material_kind, "language": material.language,
                          "version_expression": link.version_expression, "version_status": link.version_status,
                          "evidence_grade": material.evidence_grade, "sha256": material.sha256,
                          "source_url": material.source_url,
                          "download_url": f"/materials/{material.id}/download"})
    return {"product": {"id": product.id, "name": product.name}, "items": items, "total": len(items)}


@app.get("/api/vulnerabilities/{entry_id}")
def vulnerability_detail_api(entry_id: str, product_id: int | None = None, version: str = "",
                             db: DBSession = Depends(get_db), user: User = Depends(current_user)):
    entry = db.scalar(select(KnowledgeEntry).where(KnowledgeEntry.id == entry_id,
                                                   KnowledgeEntry.status == "published")
                       .options(joinedload(KnowledgeEntry.products).joinedload(ProductVulnerability.product)
                                .joinedload(Product.organization),
                                joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.reproduction),
                                joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.source_document)))
    if entry is None:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    entry_products = entry.products
    if product_id is not None and not any(relation.product_id == product_id for relation in entry_products):
        raise HTTPException(status_code=404, detail="漏洞与该产品无关联")
    products = [{"id": relation.product.id, "name": relation.product.name,
                 "company": relation.product.organization.name if relation.product.organization else "未知厂商",
                 "version": relation.version_expression, "version_status": relation.version_status,
                 "impact": relation.impact, "confidence": relation.match_confidence}
                for relation in entry_products if product_id is None or relation.product_id == product_id]
    materials = []
    for material in entry.materials:
        if material.review_status != "approved":
            continue
        applicable = db.scalars(select(ProductMaterialApplicability).where(
            ProductMaterialApplicability.material_id == material.id,
            *( [ProductMaterialApplicability.product_id == product_id] if product_id is not None else []))).all()
        if product_id is not None:
            usable = _applicable_materials(db, entry.id, product_id, version)
            if material.id not in {item.id for item in usable}:
                continue
        elif not applicable:
            continue
        package = material.reproduction
        materials.append({"id": material.id, "kind": material.material_kind, "language": material.language,
                          "evidence_grade": material.evidence_grade, "sha256": material.sha256,
                          "download_url": f"/materials/{material.id}/download",
                          "source": {"url": material.source_url, "revision": material.source_revision,
                                     "source_key": material.source_document.source_key,
                                     "title": material.source_document.title},
                          "applicable_product_ids": [link.product_id for link in applicable],
                          "reproduction": ({"prerequisites": package.prerequisites,
                                            "instructions": package.instructions,
                                            "success_criteria": package.success_criteria,
                                            "tested_versions": package.tested_versions,
                                            "execution_recorded": package.execution_recorded} if package else None)})
    return {"id": entry.id, "title": entry.title, "summary": entry.summary, "cve_id": entry.cve_id,
            "cwe_ids": entry.cwe_ids, "vuln_type": entry.vuln_type, "special_topic": entry.special_topic,
            "products": products, "materials": materials}


@app.get("/v/{entry_id}", response_class=HTMLResponse)
def detail(request: Request, entry_id: str, db: DBSession = Depends(get_db), user: User | None = Depends(optional_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    entry = db.scalar(select(KnowledgeEntry).where(KnowledgeEntry.id == entry_id,
                                                   KnowledgeEntry.status == "published")
                       .options(joinedload(KnowledgeEntry.products).joinedload(ProductVulnerability.product),
                                joinedload(KnowledgeEntry.products).joinedload(ProductVulnerability.product).joinedload(Product.organization),
                                joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.reproduction),
                                joinedload(KnowledgeEntry.materials).joinedload(MaterialVariant.source_document),
                                joinedload(KnowledgeEntry.materials)
                                .joinedload(MaterialVariant.product_applicabilities)
                                .joinedload(ProductMaterialApplicability.product)
                                .joinedload(Product.organization)))
    if not entry:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    products = []
    for rel in entry.products:
        products.append({"product": rel.product.name, "company": rel.product.organization.name if rel.product.organization else "未知厂商",
                         "version": rel.version_expression or "版本未知", "version_status": rel.version_status,
                         "impact": rel.impact, "confidence": rel.match_confidence})
    materials = [m for m in entry.materials if m.review_status == "approved" and m.product_applicabilities]
    return templates.TemplateResponse(request=request, name="detail.html",
                                      context=page_context(request, user=user, entry=entry, products=products, materials=materials))


@app.get("/materials/{material_id}/download")
def download(material_id: str, db: DBSession = Depends(get_db), user: User = Depends(current_user)):
    material = db.scalar(select(MaterialVariant).join(KnowledgeEntry).where(
        MaterialVariant.id == material_id, MaterialVariant.review_status == "approved",
        KnowledgeEntry.status == "published"))
    if not material:
        raise HTTPException(status_code=404, detail="材料不可用")
    try:
        body = ObjectStore().read(material.object_key)
    except (OSError, ValueError):
        raise HTTPException(status_code=410, detail="对象缺失")
    extension = {"poc": "poc.txt", "exp": "exp.txt", "procedure": "procedure.txt", "other": "material.txt"}.get(
        material.material_kind, "material.txt")
    return StreamingResponse(iter([body]), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{material.sha256}.{extension}"',
                                      "X-Content-Type-Options": "nosniff"})


def _admin_user(user: User = Depends(require_roles("admin"))) -> User:
    return user


def _editor_user(user: User = Depends(require_roles("admin", "editor"))) -> User:
    return user


def _verify_csrf(request: Request) -> None:
    csrf_check(request)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: User = Depends(_editor_user), db: DBSession = Depends(get_db)):
    config = db.scalar(select(AIProviderConfig).order_by(AIProviderConfig.id).limit(1))
    jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(30)).all()
    candidates = db.scalars(select(KnowledgeEntry).where(KnowledgeEntry.status == "candidate")
                            .order_by(KnowledgeEntry.first_seen_at.desc()).limit(50)).all()
    users = db.scalars(select(User).order_by(User.username)).all()
    context = page_context(request, user=user, ai_config=config, jobs=jobs, candidates=candidates, users=users)
    return templates.TemplateResponse(request=request, name="admin.html", context=context)


class JobRequest(BaseModel):
    source: str
    repo: str | None = None
    budget: int = Field(default=100, ge=1, le=500)


class GitHubDiscoveryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=240)
    pages: int = Field(default=1, ge=1, le=10)
    file_budget: int = Field(default=100, ge=1, le=500)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["viewer", "editor", "admin"] = "viewer"


@app.post("/api/admin/users")
def create_user(payload: UserCreateRequest, request: Request, user: User = Depends(_admin_user),
                _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    if db.scalar(select(User.id).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="用户名已存在")
    account = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(account)
    db.commit()
    return {"id": account.id, "username": account.username, "role": account.role}


@app.post("/api/admin/jobs")
def create_job(payload: JobRequest, request: Request, user: User = Depends(_editor_user),
               _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    if payload.source not in registered_source_keys():
        raise HTTPException(status_code=400, detail="未知来源")
    if payload.source == "github_repo" and not payload.repo:
        raise HTTPException(status_code=400, detail="GitHub 仓库格式应为 owner/name")
    if payload.source == "github_repo":
        try:
            GitHubAdapter(payload.repo or "")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    job = enqueue(db, "source_crawl", {"source": payload.source, "repo": payload.repo,
                                        "budget": payload.budget, "cursor": None})
    return {"id": job.id, "state": job.state}


@app.post("/api/admin/discover/github")
def discover_github(payload: GitHubDiscoveryRequest, request: Request, user: User = Depends(_editor_user),
                    _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    job = enqueue(db, "github_discover", {"query": payload.query.strip(), "pages": payload.pages,
                                           "page": 1, "file_budget": payload.file_budget})
    return {"id": job.id, "state": job.state}


class AIConfigRequest(BaseModel):
    name: str = "default"
    base_url: str
    model: str
    api_key: str | None = None
    enabled: bool = False
    auto_publish: bool = True
    daily_budget_usd: float = Field(default=5, ge=0, le=10000)
    input_price_per_million: float = Field(default=0, ge=0)
    output_price_per_million: float = Field(default=0, ge=0)


@app.put("/api/admin/ai")
def save_ai_config(payload: AIConfigRequest, request: Request, user: User = Depends(_admin_user),
                   _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    parsed = urlparse(payload.base_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(status_code=400, detail="模型 URL 必须是有效的 http(s) 地址，且不能包含凭据、查询参数或片段")
    host = (parsed.hostname or "").lower()
    if payload.enabled and host not in {"localhost", "127.0.0.1", "::1"} and (payload.input_price_per_million <= 0 or payload.output_price_per_million <= 0):
        raise HTTPException(status_code=400, detail="远程 Provider 需填写正数输入/输出价格，以便执行每日预算限制")
    if payload.enabled and (not payload.base_url or not payload.model or not (payload.api_key or "")):
        existing = db.scalar(select(AIProviderConfig).where(AIProviderConfig.name == payload.name))
        if not existing or not payload.base_url or not payload.model or not existing.api_key_ciphertext:
            raise HTTPException(status_code=400, detail="启用审核前需提供 URL、模型名与 API Key")
    config = db.scalar(select(AIProviderConfig).where(AIProviderConfig.name == payload.name))
    if config is None:
        config = AIProviderConfig(name=payload.name, base_url=payload.base_url, model=payload.model)
        db.add(config)
    changed_credentials = (config.base_url != payload.base_url.rstrip("/") or config.model != payload.model or bool(payload.api_key))
    config.base_url, config.model = payload.base_url.rstrip("/"), payload.model
    if payload.api_key:
        config.api_key_ciphertext = encrypt_secret(payload.api_key)
    if changed_credentials:
        config.capability_tested_at = None
    config.enabled = payload.enabled
    config.auto_publish = payload.auto_publish and config.capability_tested_at is not None
    config.daily_budget_usd = payload.daily_budget_usd
    config.input_price_per_million = payload.input_price_per_million
    config.output_price_per_million = payload.output_price_per_million
    db.commit()
    return {"saved": True, "api_key": "configured" if config.api_key_ciphertext else "missing",
            "auto_publish": config.auto_publish, "test_required": config.capability_tested_at is None}


class AIProbeRequest(BaseModel):
    auto_publish: bool = False


@app.post("/api/admin/probe/ai")
async def probe_ai(payload: AIProbeRequest, request: Request, user: User = Depends(_admin_user),
                   _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    config = db.scalar(select(AIProviderConfig).order_by(AIProviderConfig.id).limit(1))
    if not config or not config.enabled or not config.api_key_ciphertext:
        raise HTTPException(status_code=409, detail="请先保存并启用模型配置")
    from vuln_kb.security import decrypt_secret
    base = config.base_url.rstrip("/")
    endpoint = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            response = await client.post(endpoint, headers={"Authorization": f"Bearer {decrypt_secret(config.api_key_ciphertext)}"},
                                         json={"model": config.model, "temperature": 0,
                                               "response_format": {"type": "json_object"},
                                               "messages": [{"role": "user", "content": "Return JSON only: {\"ok\": true}"}]})
            response.raise_for_status()
            data = response.json()
        text = data["choices"][0]["message"]["content"]
        import json
        decoded = json.loads(text)
        if not isinstance(decoded, dict):
            raise ValueError("model output was not a JSON object")
        config.capability_tested_at = datetime.now(timezone.utc)
        config.auto_publish = bool(payload.auto_publish)
        db.commit()
        return {"ok": True, "model": config.model, "response_format": "json_object",
                "auto_publish": config.auto_publish, "tested_at": config.capability_tested_at.isoformat(),
                "response": str(text)[:300]}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"模型连接/能力探测失败：{str(exc)[:300]}")


@app.post("/api/admin/probe/github")
async def probe_github(request: Request, payload: JobRequest, user: User = Depends(_editor_user),
                       _: None = Depends(_verify_csrf)):
    try:
        return await GitHubAdapter(payload.repo or "").probe()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"GitHub 探测失败：{str(exc)[:300]}")


@app.post("/api/admin/probe/exploitdb")
async def probe_exploitdb(request: Request, user: User = Depends(_editor_user), _: None = Depends(_verify_csrf)):
    try:
        return await ExploitDBAdapter().probe()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Exploit-DB 探测失败：{str(exc)[:300]}")


@app.post("/api/admin/entries/{entry_id}/publish")
def publish_candidate(entry_id: str, request: Request, user: User = Depends(_editor_user),
                      _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    entry = db.get(KnowledgeEntry, entry_id)
    if not entry or entry.status != "candidate":
        raise HTTPException(status_code=404, detail="候选记录不存在")
    try:
        event = publish_entry(db, entry)
        db.commit()
    except PublicationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"published": True, "publication_revision": event.publication_revision}


class MaterialRevokeRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1200)


@app.post("/api/admin/materials/{material_id}/revoke")
def revoke_material_api(material_id: str, payload: MaterialRevokeRequest, request: Request,
                        user: User = Depends(_editor_user), _: None = Depends(_verify_csrf),
                        db: DBSession = Depends(get_db)):
    material = db.get(MaterialVariant, material_id)
    if material is None:
        raise HTTPException(status_code=404, detail="材料不存在")
    try:
        entry_remains_searchable = revoke_material(db, material, payload.reason)
        db.commit()
    except PublicationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"revoked": True, "entry_remains_searchable": entry_remains_searchable}


@app.post("/api/admin/entries/{entry_id}/review")
def requeue_review(entry_id: str, request: Request, user: User = Depends(_editor_user),
                   _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    entry = db.get(KnowledgeEntry, entry_id)
    if not entry or entry.status != "candidate":
        raise HTTPException(status_code=404, detail="候选记录不存在")
    materials = db.scalars(select(MaterialVariant).where(MaterialVariant.entry_id == entry_id,
                                                         MaterialVariant.review_status == "pending")).all()
    if not materials:
        raise HTTPException(status_code=409, detail="没有待审核材料")
    for material in materials:
        enqueue(db, "review_material", {"material_id": material.id})
    return {"queued": len(materials)}


@app.post("/api/admin/export")
def export_now(request: Request, user: User = Depends(_admin_user), _: None = Depends(_verify_csrf), db: DBSession = Depends(get_db)):
    final = publish_export(db)
    return {"generation": final.name, "index": str(final / "index.md")}


@app.get("/admin/jobs")
def job_list(user: User = Depends(_admin_user), db: DBSession = Depends(get_db)):
    jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(100)).all()
    return [{"id": x.id, "kind": x.kind, "state": x.state, "attempts": x.attempts,
             "created_at": x.created_at.isoformat(), "error": x.last_error} for x in jobs]

