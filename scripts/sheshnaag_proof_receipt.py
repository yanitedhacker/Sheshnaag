#!/usr/bin/env python3
"""Create and verify pinned beta proof receipts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.services.proof_receipts import (
    PROOF_CLASSES,
    PROOF_STATUSES,
    build_signed_receipt,
    generate_proof_key,
    verify_proof_receipt,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _check(value: str) -> dict[str, str]:
    try:
        check_id, status = value.split("=", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("check must use ID=STATUS") from exc
    if not check_id.strip():
        raise argparse.ArgumentTypeError("check ID is required")
    if status not in PROOF_STATUSES:
        raise argparse.ArgumentTypeError(
            f"check status must be one of: {', '.join(sorted(PROOF_STATUSES))}"
        )
    return {"id": check_id.strip(), "status": status, "detail": ""}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage signed Sheshnaag beta proof receipts.")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="Create or inspect an Ed25519 proof key.")
    keygen.add_argument("--key", required=True)

    create = commands.add_parser("create", help="Sign one proof receipt from evidence files.")
    create.add_argument("--proof-class", choices=sorted(PROOF_CLASSES), required=True)
    create.add_argument("--status", choices=sorted(PROOF_STATUSES), default="passed")
    create.add_argument("--git-commit", required=True)
    create.add_argument("--deployment-profile", required=True)
    create.add_argument("--artifact", action="append", required=True)
    create.add_argument("--check", action="append", type=_check, required=True)
    create.add_argument("--key", required=True)
    create.add_argument("--issuer", required=True)
    create.add_argument("--issued-at", default=None)
    create.add_argument("--output", required=True)

    verify = commands.add_parser("verify", help="Verify one receipt and all evidence files.")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--proof-class", choices=sorted(PROOF_CLASSES), required=True)
    verify.add_argument("--git-commit", required=True)
    verify.add_argument("--trusted-fingerprint", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "keygen":
        result = generate_proof_key(args.key)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "create":
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        receipt = build_signed_receipt(
            proof_class=args.proof_class,
            status=args.status,
            subject={
                "system": "sheshnaag",
                "git_commit": args.git_commit,
                "deployment_profile": args.deployment_profile,
            },
            checks=args.check,
            artifact_paths=[Path(path) for path in args.artifact],
            base_dir=output.parent,
            private_key_path=args.key,
            issuer=args.issuer,
            issued_at=args.issued_at or _utc_now(),
        )
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "created",
                    "receipt_path": str(output),
                    "proof_class": args.proof_class,
                    "payload_sha256": receipt["integrity"]["payload_sha256"],
                    "key_fingerprint": receipt["integrity"]["key_fingerprint"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    result = verify_proof_receipt(
        args.receipt,
        expected_proof_class=args.proof_class,
        expected_git_commit=args.git_commit,
        trusted_fingerprint=args.trusted_fingerprint,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
