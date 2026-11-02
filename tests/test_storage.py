from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vuln_kb.database import Base
from vuln_kb.models import ObjectBlob, SourceDocument
from vuln_kb.storage import ObjectStore, register_object


class ObjectStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "objects"
        self.store = ObjectStore(self.root)
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def test_candidate_stream_promotes_atomically_to_published_namespace(self) -> None:
        content = b"synthetic material fixture"
        digest, candidate_key = self.store.put_chunks([content[:9], content[9:]], namespace="candidate")
        register_object(self.db, digest, candidate_key, len(content))
        promoted_digest, published_key, size = self.store.promote(candidate_key)
        register_object(self.db, promoted_digest, published_key, size)
        self.assertEqual(digest, promoted_digest)
        self.assertTrue(candidate_key.startswith("candidate/sha256/"))
        self.assertTrue(published_key.startswith("published/sha256/"))
        self.assertEqual(self.store.read(candidate_key), self.store.read(published_key))
        self.assertEqual(len(self.db.scalars(select(ObjectBlob)).all()), 2)

    def test_failed_or_oversized_stream_leaves_no_partial_object(self) -> None:
        def broken_chunks():
            yield b"partial"
            raise RuntimeError("simulated interrupted stream")

        with self.assertRaises(RuntimeError):
            self.store.put_chunks(broken_chunks())
        with self.assertRaises(ValueError):
            self.store.put_chunks([b"1234", b"56"], max_bytes=5)
        self.assertFalse(list(self.root.rglob(".incoming-*")))
        self.assertFalse(list(self.root.rglob("[0-9a-f]")))

    def test_async_stream_failure_cleans_staging_file(self) -> None:
        async def broken_chunks():
            yield b"part"
            raise RuntimeError("interrupted")

        with self.assertRaises(RuntimeError):
            asyncio.run(self.store.put_async_chunks(broken_chunks()))
        self.assertFalse(list(self.root.rglob(".incoming-*")))

    def test_gc_preserves_referenced_blobs_and_removes_old_registered_and_untracked(self) -> None:
        keep_digest, keep_key = self.store.put(b"referenced", namespace="candidate")
        register_object(self.db, keep_digest, keep_key, len(b"referenced"))
        self.db.add(SourceDocument(source_key="fixture", external_id="kept", url="https://fixture.invalid/kept",
                                   raw_object_key=keep_key, raw_sha256=keep_digest))

        orphan_digest, orphan_key = self.store.put(b"orphan", namespace="candidate")
        register_object(self.db, orphan_digest, orphan_key, len(b"orphan"))
        orphan_row = self.db.scalar(select(ObjectBlob).where(ObjectBlob.sha256 == orphan_digest))
        orphan_row.created_at = datetime.now(timezone.utc) - timedelta(days=2)

        _, untracked_key = self.store.put(b"untracked", namespace="published")
        untracked_path = self.root.joinpath(*untracked_key.split("/"))
        old = datetime.now().timestamp() - 2 * 86400
        os.utime(untracked_path, (old, old))
        self.db.commit()

        result = self.store.collect_orphans(self.db, grace_seconds=0)
        self.assertEqual(result, {"registered": 1, "untracked": 1})
        self.assertEqual(self.store.read(keep_key), b"referenced")
        self.assertFalse(untracked_path.exists())
        self.assertFalse(self.store._path_for(orphan_key).exists())

    def test_object_key_cannot_escape_managed_namespaces(self) -> None:
        for key in ("../secret", "candidate/../../secret", "published/sha256/aa/not-a-hash", "bad/sha256/aa/" + "a" * 64):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.store.read(key)


if __name__ == "__main__":
    unittest.main()
