"""Temporary hybrid-KEX adapter for Tan's file-protection pipeline.

This module lets the encryption/package work proceed before Thang exposes a
final hybrid API.  It runs both protocol roles locally, using the existing
P-256, ML-KEM-768 and HKDF-SHA-256 implementations, and returns the same
public contract that the final integration should preserve.

Run the self-check from the repository root with either command::

    python -m Tan_Encryption.hybrid_kex_stub
    python Tan_Encryption/hybrid_kex_stub.py

The command never prints or serializes private keys, component shared secrets,
or the derived session key.
"""

from __future__ import annotations

import base64
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final


# Allow direct execution from an IDE while keeping normal imports package-like.
if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from Thang_Key_Exchange.classical_kex import (  # noqa: E402
    derive_shared_secret,
    generate_keypair,
)
from Thang_Key_Exchange.kdf import derive_session_key, transcript_hash  # noqa: E402
from Thang_Key_Exchange.ml_kem import MLKEM  # noqa: E402


ALGORITHM_ID: Final[str] = "P256_MLKEM768_HYBRID"
GROUP_ID: Final[bytes] = b"nhom_7"
HKDF_INFO: Final[bytes] = (
    b"CryptoShield/nhom_7/v1/"
    b"P256-MLKEM768-HYBRID/AES-256-GCM"
)
SESSION_ID_SIZE: Final[int] = 16
SESSION_KEY_SIZE: Final[int] = 32


@dataclass(frozen=True)
class HybridKexResult:
    """One role's input to Tan's pipeline.

    ``session_key`` is secret and must stay in memory.  All remaining byte
    fields are public protocol data that may be bound into the package header,
    AAD and signature.
    """

    algorithm_id: str
    session_id: bytes
    session_key: bytes
    transcript_hash: bytes
    sender_ecdh_public: bytes
    receiver_ecdh_public: bytes
    receiver_mlkem_public: bytes
    mlkem_ciphertext: bytes

    def __post_init__(self) -> None:
        if self.algorithm_id != ALGORITHM_ID:
            raise ValueError("Unexpected hybrid algorithm identifier.")
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError("session_id must be exactly 16 bytes.")
        if len(self.session_key) != SESSION_KEY_SIZE:
            raise ValueError("session_key must be exactly 32 bytes.")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be exactly 32 bytes.")


@dataclass(frozen=True)
class HybridKexSession:
    """The sender and receiver views of one simulated exchange."""

    sender: HybridKexResult
    receiver: HybridKexResult


def establish_hybrid_demo() -> HybridKexSession:
    """Run a local P-256 + ML-KEM-768 exchange for integration development.

    The ECDH and ML-KEM component secrets are combined in the fixed order
    ``ECDH || ML-KEM`` and passed to HKDF-SHA-256.  Only the final 32-byte
    session keys escape this function.
    """

    session_id = os.urandom(SESSION_ID_SIZE)

    sender_ecdh = generate_keypair("P-256")
    receiver_ecdh = generate_keypair("P-256")

    sender_ecdh_secret = derive_shared_secret(
        sender_ecdh.private_key,
        receiver_ecdh.public_key,
        "P-256",
    )
    receiver_ecdh_secret = derive_shared_secret(
        receiver_ecdh.private_key,
        sender_ecdh.public_key,
        "P-256",
    )

    kem = MLKEM("ML-KEM-768")
    receiver_mlkem = kem.keygen()
    encapsulation = kem.encapsulate(receiver_mlkem.public_key)
    receiver_mlkem_secret = kem.decapsulate(
        receiver_mlkem.private_key,
        encapsulation.ciphertext,
    )

    exchange_hash = transcript_hash(
        ALGORITHM_ID.encode("ascii"),
        GROUP_ID,
        session_id,
        sender_ecdh.public_key,
        receiver_ecdh.public_key,
        receiver_mlkem.public_key,
        encapsulation.ciphertext,
    )

    sender_session_key = derive_session_key(
        sender_ecdh_secret + encapsulation.shared_secret,
        salt=exchange_hash,
        info=HKDF_INFO,
        length=SESSION_KEY_SIZE,
    )
    receiver_session_key = derive_session_key(
        receiver_ecdh_secret + receiver_mlkem_secret,
        salt=exchange_hash,
        info=HKDF_INFO,
        length=SESSION_KEY_SIZE,
    )

    if sender_session_key != receiver_session_key:
        raise RuntimeError("Hybrid KEX failed: sender and receiver keys differ.")

    public_fields = {
        "algorithm_id": ALGORITHM_ID,
        "session_id": session_id,
        "transcript_hash": exchange_hash,
        "sender_ecdh_public": sender_ecdh.public_key,
        "receiver_ecdh_public": receiver_ecdh.public_key,
        "receiver_mlkem_public": receiver_mlkem.public_key,
        "mlkem_ciphertext": encapsulation.ciphertext,
    }

    return HybridKexSession(
        sender=HybridKexResult(
            session_key=sender_session_key,
            **public_fields,
        ),
        receiver=HybridKexResult(
            session_key=receiver_session_key,
            **public_fields,
        ),
    )


def public_metadata(result: HybridKexResult) -> dict[str, str]:
    """Return package-safe metadata; deliberately exclude ``session_key``."""

    def b64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    return {
        "algorithm_id": result.algorithm_id,
        "session_id": b64(result.session_id),
        "transcript_hash": b64(result.transcript_hash),
        "sender_ecdh_public": b64(result.sender_ecdh_public),
        "receiver_ecdh_public": b64(result.receiver_ecdh_public),
        "receiver_mlkem_public": b64(result.receiver_mlkem_public),
        "mlkem_ciphertext": b64(result.mlkem_ciphertext),
    }


def _self_check() -> None:
    session = establish_hybrid_demo()
    sender = session.sender
    receiver = session.receiver
    metadata = public_metadata(sender)

    assert sender.session_key == receiver.session_key
    assert sender.transcript_hash == receiver.transcript_hash
    assert "session_key" not in metadata
    assert len(sender.session_key) == SESSION_KEY_SIZE

    print("Hybrid KEX stub: OK")
    print(f"algorithm_id: {sender.algorithm_id}")
    print(f"session_id: {sender.session_id.hex()}")
    print("session_key: matched on both sides; value not displayed")
    print(f"transcript_hash: {sender.transcript_hash.hex()}")
    print(f"P-256 public key: {len(sender.sender_ecdh_public)} bytes")
    print(f"ML-KEM-768 public key: {len(sender.receiver_mlkem_public)} bytes")
    print(f"ML-KEM-768 ciphertext: {len(sender.mlkem_ciphertext)} bytes")
    print("Public metadata excludes session_key: yes")


if __name__ == "__main__":
    _self_check()
