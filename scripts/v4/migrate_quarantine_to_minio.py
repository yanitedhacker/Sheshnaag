#!/usr/bin/env python3
"""Migrate filesystem-backed quarantine objects into the MinIO bucket.

Reads every object from the local ``OBJECT_STORE_LOCAL_DIR`` (the V4
filesystem fallback layout: ``<root>/<aa>/<bb>/<digest>``), uploads it under
the same content-addressed key in MinIO, and verifies the digest before
deletion. Pass ``--dry-run`` to preview without uploading and ``--keep`` to
leave the local copy in place after upload.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_local(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix != ".tmp":
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate quarantine objects to MinIO")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--keep", action="store_true", help="Keep local copies after upload")
    parser.add_argument("--root", default=os.getenv("OBJECT_STORE_LOCAL_DIR", "./data/object_store"))
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"[migrate] local root {root} does not exist; nothing to do")
        return 0

    try:
        from app.core.object_store import MinIOBackend
    except Exception as exc:  # pragma: no cover - depends on env
        print(f"[migrate] failed to import MinIO backend: {exc}", file=sys.stderr)
        return 2

    backend = MinIOBackend(
        endpoint=os.environ["MINIO_ENDPOINT"],
        access_key=os.environ["MINIO_ACCESS_KEY"],
        secret_key=os.environ["MINIO_SECRET_KEY"],
        bucket=os.getenv("MINIO_BUCKET", "sheshnaag-quarantine"),
        secure=os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes"},
        region=os.getenv("MINIO_REGION") or None,
    )

    seen = 0
    uploaded = 0
    skipped = 0
    failures: list[tuple[str, str]] = []

    for path in _iter_local(root):
        seen += 1
        digest = path.name
        if len(digest) != 64:
            digest = _digest(path)
        actual = _digest(path)
        if actual != digest:
            failures.append((str(path), f"digest mismatch: {actual} != {digest}"))
            continue

        if args.dry_run:
            print(f"[migrate] DRY RUN would upload {digest} ({path.stat().st_size}B)")
            continue

        try:
            backend.put(digest, path.read_bytes(), content_type="application/octet-stream")
            uploaded += 1
        except Exception as exc:
            failures.append((str(path), str(exc)))
            continue

        if not args.keep:
            try:
                path.unlink()
            except OSError:
                pass

        if not backend.exists(digest):
            failures.append((str(path), "post-upload existence check failed"))
        else:
            print(f"[migrate] uploaded {digest}")

    skipped = seen - uploaded - len(failures)

    print(f"[migrate] seen={seen} uploaded={uploaded} skipped={skipped} failures={len(failures)}")
    for path, reason in failures:
        print(f"[migrate] FAILED {path}: {reason}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
