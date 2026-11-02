from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from vuln_kb.config import settings
from vuln_kb.database import get_db
from vuln_kb.models import Session, User


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, salt_text, digest_text = encoded.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_session(db: DBSession, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(Session(token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id,
                   expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.session_hours)))
    db.commit()
    return token


def current_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    token = request.cookies.get("vkb_session", "")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.get(Session, token_hash)
    expires_at = session.expires_at.replace(tzinfo=timezone.utc) if session and session.expires_at.tzinfo is None else (session.expires_at if session else None)
    if not session or expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录已失效")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="账号不可用")
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="权限不足")
        return user
    return dependency


def encrypt_secret(secret: str) -> str:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key).encrypt(secret.encode()).decode() if secret else ""


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key).decrypt(value.encode()).decode()

