#!/usr/bin/env python3
"""Bootstrap one tenant lab lead through the operator database path."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import HTTPException

from app.core.database import SessionLocal
from app.services.auth_service import AuthService


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify one tenant lab lead without exposing a public route."
    )
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-name")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        required=True,
        help="Read one password line from standard input.",
    )
    return parser


def _read_password() -> str:
    password = sys.stdin.readline().rstrip("\r\n")
    if len(password) < 12:
        raise ValueError("bootstrap_password_must_be_at_least_12_characters")
    return password


def main() -> int:
    args = _parser().parse_args()
    try:
        password = _read_password()
    except ValueError as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}), file=sys.stderr)
        return 2

    session = SessionLocal()
    try:
        result = AuthService(session).bootstrap_tenant_admin(
            tenant_name=args.tenant_name,
            tenant_slug=args.tenant_slug,
            admin_email=args.admin_email,
            admin_password=password,
            admin_name=args.admin_name,
        )
        session.commit()
    except HTTPException as exc:
        session.rollback()
        print(
            json.dumps({"status": "error", "detail": str(exc.detail)}),
            file=sys.stderr,
        )
        return 1
    finally:
        session.close()

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
