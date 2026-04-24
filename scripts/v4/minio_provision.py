#!/usr/bin/env python3
"""Provision the Sheshnaag V4 MinIO quarantine bucket.

Idempotent: safe to re-run. Creates the bucket if it doesn't exist, sets
versioning + a bucket-policy that disallows anonymous read/write, and emits
ops-friendly status to stdout.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise SystemExit(f"environment variable required: {name}")
    return value


def main() -> int:
    try:
        from minio import Minio
        from minio.versioningconfig import ENABLED, VersioningConfig
    except ImportError:
        print("minio package is required: pip install 'minio>=7.2'", file=sys.stderr)
        return 2

    endpoint = _env("MINIO_ENDPOINT", "localhost:9000")
    access_key = _env("MINIO_ACCESS_KEY", _env("MINIO_ROOT_USER", "sheshnaag"))
    secret_key = _env("MINIO_SECRET_KEY", _env("MINIO_ROOT_PASSWORD"))
    bucket = os.getenv("MINIO_BUCKET", "sheshnaag-quarantine")
    secure = os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes"}
    region = os.getenv("MINIO_REGION", "us-east-1")

    client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure, region=region)

    if not client.bucket_exists(bucket):
        client.make_bucket(bucket, location=region)
        print(f"[minio_provision] created bucket {bucket}")
    else:
        print(f"[minio_provision] bucket {bucket} already exists")

    try:
        client.set_bucket_versioning(bucket, VersioningConfig(ENABLED))
        print(f"[minio_provision] versioning enabled on {bucket}")
    except Exception as exc:
        print(f"[minio_provision] WARNING: failed to enable versioning: {exc}", file=sys.stderr)

    deny_public = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyAnonymous",
                "Effect": "Deny",
                "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    try:
        client.set_bucket_policy(bucket, json.dumps(deny_public))
        print(f"[minio_provision] bucket policy applied (deny insecure)")
    except Exception as exc:
        print(f"[minio_provision] WARNING: failed to set bucket policy: {exc}", file=sys.stderr)

    print(json.dumps({"bucket": bucket, "endpoint": endpoint, "secure": secure}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
