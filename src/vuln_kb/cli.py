from __future__ import annotations

import argparse

from vuln_kb.database import Base, SessionLocal, engine, ensure_database_parent
from vuln_kb.models import User
from vuln_kb.security import hash_password


def main():
    parser = argparse.ArgumentParser(prog="vuln-kb")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="Create or replace an admin login")
    create.add_argument("username")
    create.add_argument("password")
    args = parser.parse_args()
    ensure_database_parent()
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=args.username).one_or_none()
        if user is None:
            user = User(username=args.username, password_hash=hash_password(args.password), role="admin")
            db.add(user)
        else:
            user.password_hash, user.role, user.active = hash_password(args.password), "admin", True
        db.commit()
    print(f"admin account ready: {args.username}")


if __name__ == "__main__":
    main()

