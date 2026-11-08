from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).parents[1]


class MigrationTests(unittest.TestCase):
    def test_clean_database_upgrades_through_all_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "migration.db"
            env = os.environ.copy()
            env["DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
            env["AUTO_CREATE_SCHEMA"] = "false"
            result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT,
                                    env=env, text=True, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            engine = create_engine(f"sqlite:///{database.as_posix()}")
            try:
                inspector = inspect(engine)
                tables = set(inspector.get_table_names())
                self.assertTrue({"organization_aliases", "product_aliases", "product_identifiers",
                                 "product_material_applicability", "object_blobs", "publication_outbox",
                                 "ai_review_tasks", "ai_usage_records"} <= tables)
                ai_columns = {column["name"] for column in inspector.get_columns("ai_provider_config")}
                self.assertTrue({"configuration_revision", "capability_report", "requests_per_minute",
                                 "max_concurrent_reviews"} <= ai_columns)
                self.assertIn("task_id", {column["name"] for column in inspector.get_columns("ai_reviews")})
                columns = {column["name"] for column in inspector.get_columns("knowledge_entries")}
                self.assertIn("publication_revision", columns)
                with engine.connect() as connection:
                    version = connection.execute(text("select version_num from alembic_version")).scalar_one()
                self.assertEqual(version, "0004_ai_review_pipeline")
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
