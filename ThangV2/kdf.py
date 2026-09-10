"""Small hand-written HKDF-SHA256 helpers for the hybrid key exchange."""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

HASH_LEN: Final[int] = 32
SESSION_KEY_LEN: Final[int] = 32
DEFAULT_INFO: Final[bytes] = b"BTL/FileTransfer/v1/P256-ML768"


def _frame(part: bytes) -> bytes:
    value = bytes(part)
    return len(value).to_bytes(4, "big") + value


def transcript_hash(*parts: bytes) -> bytes:
    """SHA-256 over length-prefixed public transcript fields."""

    digest = hashlib.sha256()
    digest.update(b"BTL-HYBRID-TRANSCRIPT-v1\x00")
    for part in parts:
        digest.update(_frame(part))
    return digest.digest()


def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""

    ikm = bytes(ikm)
    if not ikm:
        raise ValueError("HKDF input keying material cannot be empty.")
    if salt is None:
        salt = b"\x00" * HASH_LEN
    else:
        salt = bytes(salt)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""

    prk = bytes(prk)
    info = bytes(info)
    if len(prk) < HASH_LEN:
        raise ValueError("HKDF PRK must be at least 32 bytes for SHA-256.")
    if not 1 <= length <= 255 * HASH_LEN:
        raise ValueError("HKDF output length must be between 1 and 8160 bytes.")

    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_session_key(
    ecdh_secret: bytes,
    mlkem_secret: bytes,
    *,
    salt: bytes,
    info: bytes = DEFAULT_INFO,
) -> bytes:
    """Combine P-256 and ML-KEM-768 secrets into one 32-byte session key.

    The two 32-byte secrets are explicitly framed before HKDF so the combiner
    input is unambiguous. ``salt`` is normally the public transcript hash.
    """

    ecdh_secret = bytes(ecdh_secret)
    mlkem_secret = bytes(mlkem_secret)
    salt = bytes(salt)
    info = bytes(info)
    if len(ecdh_secret) != 32:
        raise ValueError("ECDH shared secret must be exactly 32 bytes.")
    if len(mlkem_secret) != 32:
        raise ValueError("ML-KEM shared secret must be exactly 32 bytes.")
    if len(salt) != 32:
        raise ValueError("Hybrid KDF salt/transcript hash must be 32 bytes.")
    if not info:
        raise ValueError("HKDF info cannot be empty.")

    ikm = _frame(ecdh_secret) + _frame(mlkem_secret)
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, SESSION_KEY_LEN)


__all__ = [
    "DEFAULT_INFO",
    "SESSION_KEY_LEN",
    "derive_session_key",
    "hkdf_expand",
    "hkdf_extract",
    "transcript_hash",
]
