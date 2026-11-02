from __future__ import annotations

import asyncio
import logging
import os
import secrets
import signal
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select, update

from vuln_kb.adapters.contracts import RawSnapshot, SourceRef
from vuln_kb.adapters.github import search_repositories
from vuln_kb.adapters.registry import create_adapter
from vuln_kb.config import settings
from vuln_kb.database import Base, SessionLocal, engine, ensure_database_parent
from vuln_kb.ingestion import import_snapshot
from vuln_kb.models import CoveragePartition, Job, MaterialVariant, SourceDocument, utcnow
from vuln_kb.storage import ObjectStore

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("vuln_kb.worker")
STOP = False


def _handle_signal(*_):
    global STOP
    STOP = True


def enqueue(db, kind: str, payload: dict) -> Job:
    job = Job(kind=kind, payload=payload, state="queued")
    db.add(job)
    db.commit()
    return job


def _adapter_for(source: str, repo: str | None = None):
    return create_adapter(source, repo)


def _claim_job(db, now: datetime) -> tuple[Job, str] | None:
    eligible = or_(Job.state == "queued",
                   and_(Job.state == "running", Job.lease_until.is_not(None), Job.lease_until < now))
    job_id = db.scalar(select(Job.id).where(Job.available_at <= now, eligible)
                       .order_by(Job.created_at, Job.id).limit(1))
    if job_id is None:
        return None
    token = secrets.token_urlsafe(32)
    result = db.execute(update(Job).where(Job.id == job_id, Job.available_at <= now, eligible)
                        .values(state="running", attempts=Job.attempts + 1,
                                lease_until=now + timedelta(minutes=3), lease_token=token)
                        .execution_options(synchronize_session=False))
    db.commit()
    if result.rowcount != 1:
        return None
    job = db.get(Job, job_id)
    return (job, token) if job else None


async def _renew_lease(job_id: int, token: str) -> None:
    while True:
        await asyncio.sleep(45)
        now = datetime.now(timezone.utc)
        with SessionLocal() as heartbeat_db:
            try:
                result = heartbeat_db.execute(update(Job).where(Job.id == job_id, Job.state == "running",
                                                                Job.lease_token == token)
                                              .values(lease_until=now + timedelta(minutes=3)))
                heartbeat_db.commit()
            except Exception:
                heartbeat_db.rollback()
                log.exception("job %s lease renewal failed; will retry", job_id)
                continue
            if result.rowcount != 1:
                log.warning("job %s lease is no longer owned by this worker", job_id)
                return


async def process(job: Job, db) -> None:
    payload = job.payload or {}
    if job.kind == "github_discover":
        page_no = int(payload.get("page", 1))
        pages = max(1, min(int(payload.get("pages", 1)), 10))
        repos, total = await search_repositories(payload["query"], page=page_no, per_page=100)
        added = set()
        for repo_data in repos:
            name = repo_data.get("full_name")
            if not name or repo_data.get("private") or name in added:
                continue
            added.add(name)
            enqueue(db, "source_crawl", {"source": "github_repo", "repo": name,
                                          "budget": int(payload.get("file_budget", 100)), "cursor": None,
                                          "partition": name})
        if page_no < pages and page_no * 100 < min(total, 1000):
            enqueue(db, "github_discover", {**payload, "page": page_no + 1})
        log.info("GitHub repo search page=%s discovered=%s total=%s", page_no, len(added), total)
    elif job.kind == "source_crawl":
        adapter = _adapter_for(payload["source"], payload.get("repo"))
        partition_key = str(payload.get("partition") or payload.get("repo") or payload["source"])
        partition = db.scalar(select(CoveragePartition).where(CoveragePartition.source_key == payload["source"],
                                                              CoveragePartition.partition_key == partition_key))
        if partition is None:
            partition = CoveragePartition(source_key=payload["source"], partition_key=partition_key,
                                          state="running", cursor=payload.get("cursor"))
            db.add(partition)
            db.flush()
        partition.state, partition.cursor, partition.last_error = "running", payload.get("cursor"), None
        page = await adapter.discover(partition=payload.get("partition", ""), cursor=payload.get("cursor"), budget=int(payload.get("budget", 100)))
        partition.discovered_refs += len(page.items)
        partition.cursor = page.next_cursor
        if page.exhausted:
            partition.state, partition.last_sync_at = "complete", utcnow()
        for ref in page.items:
            enqueue(db, "material_import", {"ref": {"source_key": ref.source_key, "external_id": ref.external_id,
                                                     "title": ref.title, "url": ref.url, "metadata": ref.metadata},
                                               "source": payload["source"], "repo": payload.get("repo"),
                                               "partition": partition_key})
        if page.next_cursor is not None:
            next_payload = {**payload, "cursor": page.next_cursor, "partition": partition_key}
            enqueue(db, "source_crawl", next_payload)
        log.info("discovered source=%s count=%s next=%s", payload["source"], len(page.items), bool(page.next_cursor))
    elif job.kind == "material_import":
        ref = SourceRef(**payload["ref"])
        adapter = _adapter_for(payload["source"], payload.get("repo"))
        snapshot = await adapter.fetch(ref)
        result = await import_snapshot(db, snapshot)
        partition_key = payload.get("partition")
        if partition_key:
            partition = db.scalar(select(CoveragePartition).where(CoveragePartition.source_key == payload["source"],
                                                                  CoveragePartition.partition_key == partition_key))
            if partition:
                partition.processed_refs += 1
                db.commit()
        log.info("imported %s => %s", ref.external_id, result.get("status"))
    elif job.kind == "review_material":
        material = db.get(MaterialVariant, payload["material_id"])
        if not material:
            return
        source = db.get(SourceDocument, material.source_document_id)
        if not source or not source.raw_object_key:
            raise ValueError("source snapshot is unavailable for material review")
        ref = SourceRef(source.source_key, source.external_id, source.title, source.url, source.metadata_json or {})
        snapshot = RawSnapshot(ref, ObjectStore().read(source.raw_object_key), source.source_revision, source.license_hint)
        result = await import_snapshot(db, snapshot, force_review=True)
        log.info("reviewed material %s => %s", material.id, result.get("status"))
    else:
        raise ValueError(f"unsupported job kind: {job.kind}")


async def run() -> None:
    ensure_database_parent()
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    while not STOP:
        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            claimed = _claim_job(db, now)
            if claimed is None:
                db.close()
                await asyncio.sleep(1.5)
                continue
            job, lease_token = claimed
            heartbeat = asyncio.create_task(_renew_lease(job.id, lease_token))
            state, error_message, retry_at = "done", None, None
            try:
                await process(job, db)
            except Exception as exc:
                log.exception("job %s failed", job.id)
                db.rollback()
                if job.kind == "source_crawl":
                    payload = job.payload or {}
                    key = payload.get("partition") or payload.get("repo") or payload.get("source")
                    partition = db.scalar(select(CoveragePartition).where(CoveragePartition.source_key == payload.get("source"),
                                                                          CoveragePartition.partition_key == str(key)))
                    if partition:
                        partition.state, partition.last_error = "error", str(exc)[:4000]
                state = "queued" if job.attempts < 5 else "failed"
                error_message = str(exc)[:4000]
                retry_at = datetime.now(timezone.utc) + timedelta(seconds=min(300, 2 ** job.attempts * 3))
            finally:
                heartbeat.cancel()
                try:
                    await heartbeat
                except asyncio.CancelledError:
                    pass
            completion_values = {"state": state, "last_error": error_message,
                                 "lease_until": None, "lease_token": None}
            if retry_at is not None:
                completion_values["available_at"] = retry_at
            completed = db.execute(update(Job).where(Job.id == job.id, Job.lease_token == lease_token)
                                   .values(**completion_values))
            db.commit()
            if completed.rowcount != 1:
                log.warning("job %s completion ignored because its lease was replaced", job.id)
        finally:
            db.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    asyncio.run(run())

