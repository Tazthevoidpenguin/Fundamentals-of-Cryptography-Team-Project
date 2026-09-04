"""HKDF-SHA-256 key derivation for the CryptoShield file-transfer pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_INFO: Final[bytes] = b"CryptoShield/FileTransfer/v1/AES-256-GCM"
AES_256_KEY_SIZE: Final[int] = 32


@dataclass(frozen=True)
class SessionKeys:
    """Domain-separated keys derived from one shared secret."""

    encryption_key: bytes
    confirmation_key: bytes


def transcript_hash(*parts: bytes) -> bytes:
    """Hash a protocol transcript with unambiguous length-prefix framing.

    The result is suitable as an HKDF salt and can also be signed by the
    authentication component.  A transcript hash binds the KDF to one exchange,
    but it does not authenticate the parties by itself.
    """

    digest = hashlib.sha256()
    digest.update(b"CryptoShield-Transcript-v1\x00")
    for part in parts:
        value = bytes(part)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.digest()


def derive_session_key(
    shared_secret: bytes,
    *,
    salt: bytes | None,
    info: bytes = DEFAULT_INFO,
    length: int = AES_256_KEY_SIZE,
) -> bytes:
    """Derive one session key with HKDF-SHA-256.

    ``shared_secret`` is the ECDH or ML-KEM result.  ``salt`` should be shared
    protocol context, normally :func:`transcript_hash` over authenticated
    public exchange values.  ``info`` provides domain separation.
    """

    shared_secret = bytes(shared_secret)
    info = bytes(info)
    if not shared_secret:
        raise ValueError("Shared secret cannot be empty.")
    if not info:
        raise ValueError("HKDF info/context cannot be empty.")
    if not 1 <= length <= 255 * 32:
        raise ValueError("HKDF-SHA-256 output length must be between 1 and 8160 bytes.")
    if salt is not None:
        salt = bytes(salt)
        if not salt:
            raise ValueError("Use salt=None for an absent salt; do not pass an empty byte string.")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def derive_session_keys(shared_secret: bytes, *, salt: bytes | None) -> SessionKeys:
    """Derive separate AES and key-confirmation keys from one exchange."""

    encryption_key = derive_session_key(
        shared_secret,
        salt=salt,
        info=b"CryptoShield/FileTransfer/v1/AES-256-GCM",
        length=32,
    )
    confirmation_key = derive_session_key(
        shared_secret,
        salt=salt,
        info=b"CryptoShield/FileTransfer/v1/Key-Confirmation",
        length=32,
    )
    return SessionKeys(encryption_key=encryption_key, confirmation_key=confirmation_key)


__all__ = [
    "AES_256_KEY_SIZE",
    "DEFAULT_INFO",
    "SessionKeys",
    "derive_session_key",
    "derive_session_keys",
    "transcript_hash",
]
