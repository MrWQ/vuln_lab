from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from collections.abc import AsyncIterable
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_kb.config import settings
from vuln_kb.models import MaterialVariant, ObjectBlob, SourceDocument, SourceRevision

NAMESPACES = frozenset({"candidate", "published"})


class ObjectStore:
    """Immutable SHA-256 addressed storage; source payloads are never executed."""

    def __init__(self, root: Path | None = None):
        self.root = root or settings.object_store_dir

    def put(self, content: bytes, *, namespace: str = "candidate") -> tuple[str, str]:
        return self.put_chunks((content,), namespace=namespace)

    def put_chunks(self, chunks: Iterable[bytes], *, max_bytes: int | None = None,
                   namespace: str = "candidate") -> tuple[str, str]:
        """Atomically persist a byte stream without holding a second full copy in memory.

        The temporary object is in the destination filesystem, so ``os.replace`` is
        atomic. Oversized or failed writes are discarded and can never be referenced
        as a complete object by the database.
        """
        namespace = self._namespace(namespace)
        limit = max_bytes if max_bytes is not None else settings.max_object_size_bytes
        if limit <= 0:
            raise ValueError("max_bytes must be positive")
        self.root.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".incoming-", dir=self.root)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(fd, "wb") as stream:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise TypeError("object chunks must be bytes")
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"object exceeds configured size limit ({limit} bytes)")
                    digest.update(chunk)
                    stream.write(chunk)
                if size == 0:
                    raise ValueError("object cannot be empty")
                stream.flush()
                os.fsync(stream.fileno())
            hex_digest = digest.hexdigest()
            key = f"{namespace}/sha256/{hex_digest[:2]}/{hex_digest}"
            path = self._path_for(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = hashlib.sha256(path.read_bytes()).hexdigest()
                if existing == hex_digest:
                    os.unlink(temp_name)
                else:
                    os.replace(temp_name, path)
            else:
                os.replace(temp_name, path)
            return hex_digest, key
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    async def put_async_chunks(self, chunks: AsyncIterable[bytes], *, max_bytes: int | None = None,
                               namespace: str = "candidate") -> tuple[str, str, int]:
        """Consume an asynchronous download stream directly into the object store."""
        namespace = self._namespace(namespace)
        limit = max_bytes if max_bytes is not None else settings.max_object_size_bytes
        if limit <= 0:
            raise ValueError("max_bytes must be positive")
        self.root.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".incoming-", dir=self.root)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(fd, "wb") as stream:
                async for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise TypeError("object chunks must be bytes")
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"object exceeds configured size limit ({limit} bytes)")
                    digest.update(chunk)
                    stream.write(chunk)
                if size == 0:
                    raise ValueError("object cannot be empty")
                stream.flush()
                os.fsync(stream.fileno())
            hex_digest = digest.hexdigest()
            key = f"{namespace}/sha256/{hex_digest[:2]}/{hex_digest}"
            path = self._path_for(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = hashlib.sha256(path.read_bytes()).hexdigest()
                if existing == hex_digest:
                    os.unlink(temp_name)
                else:
                    os.replace(temp_name, path)
            else:
                os.replace(temp_name, path)
            return hex_digest, key, size
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def read(self, object_key: str) -> bytes:
        path, digest = self._parse_key(object_key)
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("object hash mismatch")
        return content

    def promote(self, object_key: str) -> tuple[str, str, int]:
        """Atomically copy a verified candidate into the immutable published namespace."""
        source_path, digest = self._parse_key(object_key)
        source_hash = hashlib.sha256()
        size = 0

        def chunks():
            nonlocal size
            with source_path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    source_hash.update(chunk)
                    size += len(chunk)
                    yield chunk

        computed, published_key = self.put_chunks(chunks(), namespace="published")
        if computed != digest or source_hash.hexdigest() != digest:
            self.delete(published_key)
            raise ValueError("object hash mismatch during promotion")
        return computed, published_key, size

    def delete(self, object_key: str) -> bool:
        path, _ = self._parse_key(object_key)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        self._remove_empty_parents(path.parent)
        return True

    def _namespace(self, namespace: str) -> str:
        if namespace not in NAMESPACES:
            raise ValueError("object namespace must be candidate or published")
        return namespace

    def _parse_key(self, object_key: str) -> tuple[Path, str]:
        parts = object_key.split("/")
        if len(parts) == 4 and parts[0] in NAMESPACES and parts[1] == "sha256":
            namespace, _, prefix, digest = parts
            path = self.root / namespace / "sha256" / prefix / digest
        elif len(parts) == 3 and parts[0] == "sha256":
            # Read-only compatibility for objects written before namespace support.
            _, prefix, digest = parts
            path = self.root / prefix / digest
        else:
            raise ValueError("invalid object key")
        if (len(digest) != 64 or prefix != digest[:2]
                or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("invalid object key")
        return path, digest

    def _path_for(self, object_key: str) -> Path:
        return self._parse_key(object_key)[0]

    def _remove_empty_parents(self, path: Path) -> None:
        stop = self.root.resolve()
        current = path
        while current != stop and stop in current.resolve().parents:
            try:
                current.rmdir()
            except OSError:
                break
            current = current.parent

    def collect_orphans(self, db: Session, *, grace_seconds: int = 86400,
                        now: datetime | None = None) -> dict[str, int]:
        """Remove unreferenced registered blobs and old untracked complete files."""
        if grace_seconds < 0:
            raise ValueError("grace_seconds cannot be negative")
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=grace_seconds)
        referenced = set(db.scalars(select(SourceDocument.raw_object_key).where(SourceDocument.raw_object_key.is_not(None)))
                         .all())
        referenced.update(db.scalars(select(SourceRevision.object_key)).all())
        referenced.update(db.scalars(select(MaterialVariant.object_key)).all())
        removed_registered = 0
        for blob in db.scalars(select(ObjectBlob)).all():
            created = blob.created_at
            created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
            if blob.object_key in referenced or created > cutoff:
                continue
            self.delete(blob.object_key)
            db.delete(blob)
            removed_registered += 1
        db.flush()

        registered = set(db.scalars(select(ObjectBlob.object_key)).all())
        removed_untracked = 0
        for key, path in self._iter_object_files():
            if key in registered:
                continue
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if modified <= cutoff:
                self.delete(key)
                removed_untracked += 1
        db.commit()
        return {"registered": removed_registered, "untracked": removed_untracked}

    def _iter_object_files(self):
        if not self.root.exists():
            return
        for namespace in NAMESPACES:
            base = self.root / namespace / "sha256"
            if not base.exists():
                continue
            for path in base.glob("[0-9a-f][0-9a-f]/*"):
                if path.is_file() and len(path.name) == 64 and path.parent.name == path.name[:2]:
                    yield f"{namespace}/sha256/{path.parent.name}/{path.name}", path
        legacy = self.root / "sha256"
        if legacy.exists():
            for path in legacy.glob("[0-9a-f][0-9a-f]/*"):
                if path.is_file() and len(path.name) == 64 and path.parent.name == path.name[:2]:
                    yield f"sha256/{path.parent.name}/{path.name}", path


def register_object(db: Session, sha256: str, object_key: str, size_bytes: int) -> ObjectBlob:
    namespace = object_key.split("/", 1)[0]
    if namespace not in NAMESPACES:
        # Newly imported objects must use a managed namespace; old rows are read-only legacy.
        raise ValueError("cannot register a legacy namespace object")
    row = db.scalar(select(ObjectBlob).where(ObjectBlob.namespace == namespace, ObjectBlob.sha256 == sha256))
    if row is None:
        row = ObjectBlob(namespace=namespace, sha256=sha256, object_key=object_key, size_bytes=size_bytes)
        db.add(row)
        db.flush()
    elif row.object_key != object_key or row.size_bytes != size_bytes:
        raise ValueError("object inventory hash collision or inconsistent metadata")
    return row

