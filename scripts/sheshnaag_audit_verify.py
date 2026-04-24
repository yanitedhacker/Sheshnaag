#!/usr/bin/env python3
"""Sheshnaag V4 audit chain verifier.

Walks the Merkle-chained ``audit_log_entries`` table end-to-end, re-computes
each row's hash, verifies every signature, and exits non-zero on any failure.

Usage::

    python -m scripts.sheshnaag_audit_verify [--since=N] [--json]

The script connects to the database configured by the normal
``SHESHNAAG_DATABASE_URL`` / ``DATABASE_URL`` env vars (via
``app.core.config.settings.database_url``).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Allow `python scripts/sheshnaag_audit_verify.py` alongside
# `python -m scripts.sheshnaag_audit_verify`.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database import SessionLocal  # noqa: E402
from app.services.capability_policy import CapabilityPolicy  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the Sheshnaag V4 Merkle audit chain."
    )
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="Only verify rows with idx >= SINCE (still chains from the row before SINCE).",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit machine-readable JSON instead of human text.",
    )
    args = parser.parse_args(argv)

    session = SessionLocal()
    try:
        policy = CapabilityPolicy(session)
        root = policy.latest_root()
        result = policy.verify_chain(since=args.since)
    finally:
        session.close()

    payload = {
        "ok": result.ok,
        "last_verified_idx": result.last_verified_idx,
        "first_bad_idx": result.first_bad_idx,
        "reason": result.reason,
        "latest_root": root,
    }

    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        status = "OK" if result.ok else "FAIL"
        print(f"[{status}] audit chain verification")
        print(f"  last_verified_idx: {result.last_verified_idx}")
        print(f"  first_bad_idx:     {result.first_bad_idx}")
        print(f"  reason:            {result.reason}")
        print(f"  latest_root:       idx={root['idx']} hash={root['entry_hash']}")

    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
