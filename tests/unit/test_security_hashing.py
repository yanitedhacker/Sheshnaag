"""Unit tests for password hashing compatibility."""

from passlib.context import CryptContext

from app.core.security import get_password_hash, verify_password


def test_get_password_hash_uses_argon2_for_new_hashes():
    hashed = get_password_hash("supersecure123")
    assert hashed.startswith("$argon2")
    assert verify_password("supersecure123", hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_verify_password_accepts_legacy_bcrypt_hashes():
    legacy_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    legacy_hash = legacy_context.hash("supersecure123")

    assert legacy_hash.startswith("$2")
    assert verify_password("supersecure123", legacy_hash) is True
    assert verify_password("wrong-password", legacy_hash) is False
