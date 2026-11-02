from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_local_env(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE local settings without overriding process environment."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if name and name.replace("_", "").isalnum() and name not in os.environ:
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            os.environ[name] = value


_load_local_env()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/vuln-kb.db")
    object_store_dir: Path = Path(os.getenv("OBJECT_STORE_DIR", "./data/objects"))
    max_object_size_bytes: int = int(os.getenv("MAX_OBJECT_SIZE_BYTES", str(25 * 1024 * 1024)))
    export_dir: Path = Path(os.getenv("EXPORT_DIR", "./data/exports"))
    sources_config: Path = Path(os.getenv("SOURCES_CONFIG", "./configs/sources.yml"))
    secret_key: str = os.getenv("SECRET_KEY", "development-only-change-me")
    bootstrap_admin_username: str = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    bootstrap_admin_password: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    ai_base_url: str = os.getenv("AI_BASE_URL", "")
    ai_model: str = os.getenv("AI_MODEL", "")
    ai_api_key: str = os.getenv("AI_API_KEY", "")
    ai_review_enabled: bool = _bool("AI_REVIEW_ENABLED")
    ai_auto_publish: bool = _bool("AI_AUTO_PUBLISH")
    ai_daily_budget_usd: float = float(os.getenv("AI_DAILY_BUDGET_USD", "5"))
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")
    session_hours: int = int(os.getenv("SESSION_HOURS", "12"))
    auto_create_schema: bool = _bool("AUTO_CREATE_SCHEMA", True)


settings = Settings()

