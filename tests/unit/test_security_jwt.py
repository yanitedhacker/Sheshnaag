"""JWT behavior and dependency policy tests."""

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import create_access_token, decode_token


def test_jwt_runtime_does_not_install_python_jose() -> None:
    requirements = (
        Path(__file__).resolve().parents[2] / "requirements.txt"
    ).read_text(encoding="utf-8")
    package_lines = [
        line.strip().lower()
        for line in requirements.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert not any(line.startswith("python-jose") for line in package_lines)
    assert any(line.startswith("pyjwt[crypto]") for line in package_lines)


def test_access_token_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "secret_key", "test-key-with-at-least-thirty-two-bytes")
    monkeypatch.setattr(settings, "algorithm", "HS256")

    token = create_access_token({"sub": "alice", "scopes": ["read"]})
    payload = decode_token(token)

    assert payload["sub"] == "alice"
    assert payload["scopes"] == ["read"]
    assert {"iat", "exp"}.issubset(payload)


def test_expired_access_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "secret_key", "test-key-with-at-least-thirty-two-bytes")
    monkeypatch.setattr(settings, "algorithm", "HS256")
    token = create_access_token(
        {"sub": "alice"},
        expires_delta=timedelta(seconds=-1),
    )

    with pytest.raises(HTTPException) as exc_info:
        decode_token(token)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"
