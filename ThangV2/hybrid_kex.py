"""Hybrid P-256 + ML-KEM-768 key establishment for the group project.

The main contract is intentionally small:

* ``HybridKexResult``: result visible to the encryption module. ``session_key``
  is 32 secret bytes and must remain in RAM only.
* ``PackageHeader``: public metadata that can be placed in the encrypted-file
  package and serialized as AES-GCM AAD.

No private key, raw ECDH secret, or raw ML-KEM shared secret is put in either
package/header output.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Final

from ThangV2 import classical_kex
from ThangV2 import kdf
from ThangV2 import ml_kem

ALGORITHM_ID: Final[str] = "P256_MLKEM768_HYBRID"
SESSION_ID_SIZE: Final[int] = 16


@dataclass(frozen=True)
class HybridKexResult:
    algorithm_id: str
    session_id: bytes

    # 32-byte secret; keep in RAM only, never serialize into the package.
    session_key: bytes

    # Public exchange data; safe to place in the package/header.
    transcript_hash: bytes
    sender_ecdh_public: bytes
    receiver_ecdh_public: bytes
    receiver_mlkem_public: bytes
    mlkem_ciphertext: bytes

    def __post_init__(self) -> None:
        if self.algorithm_id != ALGORITHM_ID:
            raise ValueError(f"algorithm_id must be {ALGORITHM_ID!r}.")
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError(f"session_id must be {SESSION_ID_SIZE} bytes.")
        if len(self.session_key) != 32:
            raise ValueError("session_key must be exactly 32 bytes.")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be exactly 32 bytes.")
        if len(self.sender_ecdh_public) != 33 or len(self.receiver_ecdh_public) != 33:
            raise ValueError("P-256 public keys must use 33-byte compressed SEC1 form.")
        if len(self.receiver_mlkem_public) != ml_kem.PARAMS.public_key_bytes:
            raise ValueError("receiver_mlkem_public must be an ML-KEM-768 public key.")
        if len(self.mlkem_ciphertext) != ml_kem.PARAMS.ciphertext_bytes:
            raise ValueError("mlkem_ciphertext must be an ML-KEM-768 ciphertext.")


@dataclass(frozen=True)
class PackageHeader:
    version: int
    group_id: str
    algorithm_id: str
    session_id: bytes
    message_id: str
    sender_ecdh_public: bytes
    receiver_ecdh_public: bytes
    receiver_mlkem_public: bytes
    mlkem_ciphertext: bytes
    transcript_hash: bytes
    filename: str
    plaintext_size: int
    plaintext_hash: bytes

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("version must be >= 1.")
        if not self.group_id:
            raise ValueError("group_id cannot be empty.")
        if self.algorithm_id != ALGORITHM_ID:
            raise ValueError(f"algorithm_id must be {ALGORITHM_ID!r}.")
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError(f"session_id must be {SESSION_ID_SIZE} bytes.")
        if not self.message_id:
            raise ValueError("message_id cannot be empty.")
        if len(self.sender_ecdh_public) != 33 or len(self.receiver_ecdh_public) != 33:
            raise ValueError("P-256 public keys must use 33-byte compressed SEC1 form.")
        if len(self.receiver_mlkem_public) != ml_kem.PARAMS.public_key_bytes:
            raise ValueError("receiver_mlkem_public must be an ML-KEM-768 public key.")
        if len(self.mlkem_ciphertext) != ml_kem.PARAMS.ciphertext_bytes:
            raise ValueError("mlkem_ciphertext must be an ML-KEM-768 ciphertext.")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be exactly 32 bytes.")
        if not self.filename:
            raise ValueError("filename cannot be empty.")
        if self.plaintext_size < 0:
            raise ValueError("plaintext_size cannot be negative.")
        if len(self.plaintext_hash) != 32:
            raise ValueError("plaintext_hash must be a 32-byte SHA-256 digest.")

    def to_aad(self) -> bytes:
        """Canonical binary encoding suitable for AES-GCM AAD.

        This encoding contains public metadata only.  It deliberately excludes
        the 32-byte session key because that key must never be transmitted.
        """

        return b"".join(
            (
                b"BTL-PACKAGE-HEADER-v1\x00",
                self.version.to_bytes(4, "big"),
                _frame_text(self.group_id),
                _frame_text(self.algorithm_id),
                _frame_bytes(self.session_id),
                _frame_text(self.message_id),
                _frame_bytes(self.sender_ecdh_public),
                _frame_bytes(self.receiver_ecdh_public),
                _frame_bytes(self.receiver_mlkem_public),
                _frame_bytes(self.mlkem_ciphertext),
                _frame_bytes(self.transcript_hash),
                _frame_text(self.filename),
                self.plaintext_size.to_bytes(8, "big"),
                _frame_bytes(self.plaintext_hash),
            )
        )


def _frame_bytes(value: bytes) -> bytes:
    value = bytes(value)
    return len(value).to_bytes(4, "big") + value


def _frame_text(value: str) -> bytes:
    return _frame_bytes(value.encode("utf-8"))


def compute_transcript_hash(
    *,
    session_id: bytes,
    sender_ecdh_public: bytes,
    receiver_ecdh_public: bytes,
    receiver_mlkem_public: bytes,
    mlkem_ciphertext: bytes,
) -> bytes:
    """Bind the public hybrid exchange values to one 32-byte transcript hash."""

    return kdf.transcript_hash(
        ALGORITHM_ID.encode("ascii"),
        bytes(session_id),
        bytes(sender_ecdh_public),
        bytes(receiver_ecdh_public),
        bytes(receiver_mlkem_public),
        bytes(mlkem_ciphertext),
    )


def generate_receiver_keys(
    *,
    ecdh_private_scalar: int | None = None,
    mlkem_seed: bytes | None = None,
) -> tuple[classical_kex.P256KeyPair, ml_kem.MLKEMKeyPair]:
    """Generate receiver P-256 and ML-KEM-768 key pairs.

    The two private keys returned here are local receiver state and must not be
    placed in ``PackageHeader`` or sent over the network.
    """

    return (
        classical_kex.generate_keypair(ecdh_private_scalar),
        ml_kem.keygen(mlkem_seed),
    )


def sender_establish(
    receiver_ecdh_public: bytes,
    receiver_mlkem_public: bytes,
    *,
    session_id: bytes | None = None,
    sender_ecdh_private_scalar: int | None = None,
    mlkem_randomness: bytes | None = None,
) -> HybridKexResult:
    """Sender side of the hybrid exchange.

    The sender combines its P-256 ECDH secret and its ML-KEM-768 encapsulation
    secret with HKDF-SHA256 and returns the 32-byte session key plus public
    transcript values.
    """

    receiver_ecdh_public = bytes(receiver_ecdh_public)
    receiver_mlkem_public = bytes(receiver_mlkem_public)
    if session_id is None:
        session_id = secrets.token_bytes(SESSION_ID_SIZE)
    session_id = bytes(session_id)
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(f"session_id must be {SESSION_ID_SIZE} bytes.")

    sender_ecdh = classical_kex.generate_keypair(sender_ecdh_private_scalar)
    ecdh_secret = classical_kex.derive_shared_secret(
        sender_ecdh.private_key,
        receiver_ecdh_public,
    )
    kem = ml_kem.encapsulate(receiver_mlkem_public, mlkem_randomness)

    thash = compute_transcript_hash(
        session_id=session_id,
        sender_ecdh_public=sender_ecdh.public_key,
        receiver_ecdh_public=receiver_ecdh_public,
        receiver_mlkem_public=receiver_mlkem_public,
        mlkem_ciphertext=kem.ciphertext,
    )
    session_key = kdf.derive_session_key(
        ecdh_secret,
        kem.shared_secret,
        salt=thash,
    )

    return HybridKexResult(
        algorithm_id=ALGORITHM_ID,
        session_id=session_id,
        session_key=session_key,
        transcript_hash=thash,
        sender_ecdh_public=sender_ecdh.public_key,
        receiver_ecdh_public=receiver_ecdh_public,
        receiver_mlkem_public=receiver_mlkem_public,
        mlkem_ciphertext=kem.ciphertext,
    )


def make_package_header(
    kex: HybridKexResult,
    *,
    group_id: str,
    message_id: str,
    filename: str,
    plaintext_size: int,
    plaintext_hash: bytes,
    version: int = 1,
) -> PackageHeader:
    """Copy only public KEX fields into the AES-GCM package header."""

    return PackageHeader(
        version=version,
        group_id=group_id,
        algorithm_id=kex.algorithm_id,
        session_id=kex.session_id,
        message_id=message_id,
        sender_ecdh_public=kex.sender_ecdh_public,
        receiver_ecdh_public=kex.receiver_ecdh_public,
        receiver_mlkem_public=kex.receiver_mlkem_public,
        mlkem_ciphertext=kex.mlkem_ciphertext,
        transcript_hash=kex.transcript_hash,
        filename=filename,
        plaintext_size=plaintext_size,
        plaintext_hash=bytes(plaintext_hash),
    )


def receiver_establish(
    receiver_ecdh_private: bytes,
    receiver_mlkem_private: bytes,
    header: PackageHeader,
) -> HybridKexResult:
    """Receiver side: verify public context and derive the same session key."""

    expected_ecdh_public = classical_kex.public_from_private(receiver_ecdh_private)
    if not hmac.compare_digest(expected_ecdh_public, header.receiver_ecdh_public):
        raise ValueError("Header receiver ECDH public key does not match the local private key.")

    expected_mlkem_public = ml_kem.public_from_private(receiver_mlkem_private)
    if not hmac.compare_digest(expected_mlkem_public, header.receiver_mlkem_public):
        raise ValueError("Header receiver ML-KEM public key does not match the local private key.")

    expected_thash = compute_transcript_hash(
        session_id=header.session_id,
        sender_ecdh_public=header.sender_ecdh_public,
        receiver_ecdh_public=header.receiver_ecdh_public,
        receiver_mlkem_public=header.receiver_mlkem_public,
        mlkem_ciphertext=header.mlkem_ciphertext,
    )
    if not hmac.compare_digest(expected_thash, header.transcript_hash):
        raise ValueError("Hybrid transcript hash mismatch.")

    ecdh_secret = classical_kex.derive_shared_secret(
        receiver_ecdh_private,
        header.sender_ecdh_public,
    )
    mlkem_secret = ml_kem.decapsulate(
        receiver_mlkem_private,
        header.mlkem_ciphertext,
    )
    session_key = kdf.derive_session_key(
        ecdh_secret,
        mlkem_secret,
        salt=expected_thash,
    )

    return HybridKexResult(
        algorithm_id=header.algorithm_id,
        session_id=header.session_id,
        session_key=session_key,
        transcript_hash=header.transcript_hash,
        sender_ecdh_public=header.sender_ecdh_public,
        receiver_ecdh_public=header.receiver_ecdh_public,
        receiver_mlkem_public=header.receiver_mlkem_public,
        mlkem_ciphertext=header.mlkem_ciphertext,
    )


__all__ = [
    "ALGORITHM_ID",
    "HybridKexResult",
    "PackageHeader",
    "compute_transcript_hash",
    "generate_receiver_keys",
    "make_package_header",
    "receiver_establish",
    "sender_establish",
]
