"""Unit tests for the V4 object store abstraction."""

from __future__ import annotations

import hashlib

import pytest

from app.core.object_store import LocalFilesystemBackend, ObjectStore, reset_object_store


def test_local_backend_round_trip(tmp_path):
    backend = LocalFilesystemBackend(root=tmp_path)
    store = ObjectStore(backend)
    payload = b"sheshnaag-payload-v4"
    digest = hashlib.sha256(payload).hexdigest()

    stored = store.put_bytes(payload, content_type="application/octet-stream")
    assert stored.digest == digest
    assert stored.backend == "filesystem"
    assert stored.size == len(payload)
    assert store.exists(digest) is True
    assert store.read_bytes(digest) == payload


def test_local_backend_idempotent_put(tmp_path):
    backend = LocalFilesystemBackend(root=tmp_path)
    store = ObjectStore(backend)
    first = store.put_bytes(b"abc")
    second = store.put_bytes(b"abc")
    assert first.digest == second.digest
    assert first.location == second.location


def test_local_backend_health(tmp_path):
    backend = LocalFilesystemBackend(root=tmp_path)
    health = ObjectStore(backend).health()
    assert health["status"] == "ok"
    assert health["backend"] == "filesystem"


def test_factory_falls_back_to_filesystem(monkeypatch, tmp_path):
    monkeypatch.setenv("OBJECT_STORE_BACKEND", "minio")
    monkeypatch.delenv("MINIO_ENDPOINT", raising=False)
    monkeypatch.setenv("OBJECT_STORE_LOCAL_DIR", str(tmp_path))
    reset_object_store()

    store = ObjectStore.from_env()
    assert store.backend.name == "filesystem"
    reset_object_store()


def test_iter_local_objects(tmp_path):
    backend = LocalFilesystemBackend(root=tmp_path)
    store = ObjectStore(backend)
    store.put_bytes(b"alpha")
    store.put_bytes(b"beta")
    store.put_bytes(b"gamma")
    digests = {digest for digest, _ in store.iter_local_objects()}
    assert len(digests) == 3
