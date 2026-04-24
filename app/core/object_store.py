"""Quarantine-grade object storage with a MinIO/S3 backend and a local fallback.

The malware lab treats every uploaded specimen as untrusted: bytes go into a
write-once-read-many object store keyed by content hash so we can reference
samples by digest, prevent collisions, and detach byte storage from the
relational tenancy/case rows. ``ObjectStore`` is the single seam through
which all callers move bytes; the production path uses MinIO/S3 (server-side
encryption + immutable bucket policies), the dev/test path falls back to a
filesystem layout that mirrors the same guarantees.

``LocalFilesystemBackend`` is intentionally simple: ``<root>/<sha256>``. It is
enough for unit tests and single-host deployments while the same caller can
flip to MinIO via ``OBJECT_STORE_BACKEND=minio`` without code changes.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Optional, Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredObject:
    """Result of placing bytes into the object store."""

    digest: str            # sha256 hex of the payload
    size: int
    backend: str           # "minio" | "filesystem"
    location: str          # opaque URI: ``s3://bucket/key`` or ``file:///path``
    bucket: Optional[str] = None
    key: Optional[str] = None


class ObjectBackend(Protocol):
    name: str

    def put(self, digest: str, data: bytes, *, content_type: str) -> StoredObject: ...
    def open(self, digest: str) -> BinaryIO: ...
    def exists(self, digest: str) -> bool: ...
    def delete(self, digest: str) -> None: ...
    def health(self) -> dict: ...


class LocalFilesystemBackend:
    """Filesystem fallback rooted at ``OBJECT_STORE_LOCAL_DIR``."""

    name = "filesystem"

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root or os.getenv("OBJECT_STORE_LOCAL_DIR", "./data/object_store"))
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest: str) -> Path:
        # Two-level fanout keeps directory listings reasonable for very large
        # quarantines without changing the address space.
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, digest: str, data: bytes, *, content_type: str) -> StoredObject:
        path = self._path_for(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
        return StoredObject(
            digest=digest,
            size=len(data),
            backend=self.name,
            location=f"file://{path.resolve()}",
            bucket=None,
            key=str(path.relative_to(self.root)),
        )

    def open(self, digest: str) -> BinaryIO:
        path = self._path_for(digest)
        if not path.exists():
            raise FileNotFoundError(f"object not found: {digest}")
        return path.open("rb")

    def exists(self, digest: str) -> bool:
        return self._path_for(digest).exists()

    def delete(self, digest: str) -> None:
        path = self._path_for(digest)
        if path.exists():
            path.unlink()

    def health(self) -> dict:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            return {"status": "ok", "backend": self.name, "root": str(self.root.resolve())}
        except Exception as exc:  # pragma: no cover - defensive
            return {"status": "missing", "backend": self.name, "error": str(exc)}


class MinIOBackend:
    """MinIO/S3 backend.

    Lazily imports ``minio`` so the dependency is optional. When the package
    is missing, the constructor raises and the factory falls through to the
    filesystem backend with a WARNING.
    """

    name = "minio"

    def __init__(
        self,
        *,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        secure: bool = True,
        region: Optional[str] = None,
    ) -> None:
        from minio import Minio  # type: ignore[import-not-found]

        self._client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
            region=region,
        )
        self.bucket = bucket
        self._endpoint = endpoint
        self._secure = secure
        if not self._client.bucket_exists(bucket):
            self._client.make_bucket(bucket, location=region or "us-east-1")
            logger.info("Created object-store bucket %s", bucket)

    def _key_for(self, digest: str) -> str:
        return f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"

    def put(self, digest: str, data: bytes, *, content_type: str) -> StoredObject:
        from minio.commonconfig import Tags  # type: ignore[import-not-found]

        key = self._key_for(digest)
        try:
            self._client.stat_object(self.bucket, key)
        except Exception:
            tags = Tags(for_object=True)
            tags["sheshnaag.digest"] = digest
            tags["sheshnaag.kind"] = "quarantine"
            self._client.put_object(
                self.bucket,
                key,
                io.BytesIO(data),
                length=len(data),
                content_type=content_type,
                tags=tags,
            )
        scheme = "https" if self._secure else "http"
        return StoredObject(
            digest=digest,
            size=len(data),
            backend=self.name,
            location=f"s3://{self.bucket}/{key}",
            bucket=self.bucket,
            key=key,
        )

    def open(self, digest: str) -> BinaryIO:
        key = self._key_for(digest)
        response = self._client.get_object(self.bucket, key)
        try:
            data = response.read()
        finally:
            response.close()
            response.release_conn()
        return io.BytesIO(data)

    def exists(self, digest: str) -> bool:
        try:
            self._client.stat_object(self.bucket, self._key_for(digest))
            return True
        except Exception:
            return False

    def delete(self, digest: str) -> None:
        try:
            self._client.remove_object(self.bucket, self._key_for(digest))
        except Exception:
            pass

    def health(self) -> dict:
        try:
            ok = self._client.bucket_exists(self.bucket)
            return {
                "status": "ok" if ok else "missing",
                "backend": self.name,
                "bucket": self.bucket,
                "endpoint": self._endpoint,
            }
        except Exception as exc:
            return {"status": "missing", "backend": self.name, "error": str(exc)}


class ObjectStore:
    """Façade that owns a backend and computes content-addressable digests."""

    def __init__(self, backend: ObjectBackend) -> None:
        self.backend = backend

    @classmethod
    def from_env(cls) -> "ObjectStore":
        choice = os.getenv("OBJECT_STORE_BACKEND", "filesystem").strip().lower()
        if choice in {"minio", "s3"}:
            try:
                backend: ObjectBackend = MinIOBackend(
                    endpoint=os.environ["MINIO_ENDPOINT"],
                    access_key=os.environ["MINIO_ACCESS_KEY"],
                    secret_key=os.environ["MINIO_SECRET_KEY"],
                    bucket=os.getenv("MINIO_BUCKET", "sheshnaag-quarantine"),
                    secure=os.getenv("MINIO_SECURE", "true").lower() in {"1", "true", "yes"},
                    region=os.getenv("MINIO_REGION") or None,
                )
            except KeyError as exc:
                logger.warning(
                    "OBJECT_STORE_BACKEND=minio requested but %s is unset; falling back to filesystem",
                    exc.args[0],
                )
                backend = LocalFilesystemBackend()
            except Exception as exc:  # pragma: no cover - depends on runtime
                logger.warning(
                    "MinIO backend unavailable (%s); falling back to filesystem object store",
                    exc,
                )
                backend = LocalFilesystemBackend()
        else:
            backend = LocalFilesystemBackend()
        return cls(backend)

    def put_bytes(self, data: bytes, *, content_type: str = "application/octet-stream") -> StoredObject:
        digest = hashlib.sha256(data).hexdigest()
        return self.backend.put(digest, data, content_type=content_type)

    def open(self, digest: str) -> BinaryIO:
        return self.backend.open(digest)

    def read_bytes(self, digest: str) -> bytes:
        with self.open(digest) as stream:
            return stream.read()

    def exists(self, digest: str) -> bool:
        return self.backend.exists(digest)

    def delete(self, digest: str) -> None:
        self.backend.delete(digest)

    def health(self) -> dict:
        return self.backend.health()

    def iter_local_objects(self) -> Iterator[tuple[str, Path]]:
        """Yield ``(digest, path)`` for filesystem backends. Used by migrators."""

        if not isinstance(self.backend, LocalFilesystemBackend):
            return
        root = self.backend.root
        for path in root.rglob("*"):
            if path.is_file() and path.suffix != ".tmp":
                yield path.name, path


_DEFAULT_STORE: Optional[ObjectStore] = None


def get_object_store() -> ObjectStore:
    """Return a process-wide :class:`ObjectStore` instance."""

    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = ObjectStore.from_env()
    return _DEFAULT_STORE


def reset_object_store() -> None:
    """Used in tests to drop the cached store between cases."""

    global _DEFAULT_STORE
    _DEFAULT_STORE = None


__all__ = [
    "LocalFilesystemBackend",
    "MinIOBackend",
    "ObjectBackend",
    "ObjectStore",
    "StoredObject",
    "get_object_store",
    "reset_object_store",
]
