"""Classical elliptic-curve Diffie-Hellman helpers for CryptoShield.

The project proposal names ECDH but does not mandate one curve.  This module
therefore supports two commonly used choices:

* ``P-256`` (secp256r1), used as the default for the coursework comparison;
* ``X25519``, exposed as an alternative compact 32-byte interface.

The returned raw ECDH value is *input keying material*, not an AES key.  Pass it
through :mod:`kdf` before encryption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


@dataclass(frozen=True)
class ECDHKeyPair:
    """Raw serialized private/public key pair for an ECDH algorithm."""

    algorithm: str
    private_key: bytes
    public_key: bytes


_ALIASES: Final[dict[str, str]] = {
    "P-256": "P-256",
    "P256": "P-256",
    "SECP256R1": "P-256",
    "PRIME256V1": "P-256",
    "X25519": "X25519",
}


def _normalize_algorithm(algorithm: str) -> str:
    key = algorithm.upper().replace("_", "-").strip()
    try:
        return _ALIASES[key]
    except KeyError as exc:
        raise ValueError("Unsupported ECDH algorithm. Choose 'P-256' or 'X25519'.") from exc


def generate_keypair(algorithm: str = "P-256") -> ECDHKeyPair:
    """Generate and serialize one ECDH key pair."""

    normalized = _normalize_algorithm(algorithm)
    if normalized == "P-256":
        private = ec.generate_private_key(ec.SECP256R1())
        private_value = private.private_numbers().private_value.to_bytes(32, "big")
        public_value = private.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.CompressedPoint,
        )
    else:
        private = x25519.X25519PrivateKey.generate()
        private_value = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_value = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return ECDHKeyPair(normalized, private_value, public_value)


def derive_shared_secret(private_key: bytes, peer_public_key: bytes, algorithm: str = "P-256") -> bytes:
    """Derive the raw ECDH shared secret from serialized keys.

    The function validates key lengths and, for P-256, delegates point
    validation to ``cryptography``.  X25519 rejects an all-zero shared result in
    the underlying library.
    """

    normalized = _normalize_algorithm(algorithm)
    private_key = bytes(private_key)
    peer_public_key = bytes(peer_public_key)

    if normalized == "P-256":
        if len(private_key) != 32:
            raise ValueError("A P-256 private scalar must be exactly 32 bytes.")
        if len(peer_public_key) not in (33, 65):
            raise ValueError("A P-256 public point must use a 33-byte compressed or 65-byte uncompressed encoding.")
        private_value = int.from_bytes(private_key, "big")
        if private_value == 0:
            raise ValueError("A P-256 private scalar cannot be zero.")
        private = ec.derive_private_key(private_value, ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key)
        return private.exchange(ec.ECDH(), peer)

    if len(private_key) != 32 or len(peer_public_key) != 32:
        raise ValueError("X25519 private and public keys must both be exactly 32 bytes.")
    private = x25519.X25519PrivateKey.from_private_bytes(private_key)
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
    return private.exchange(peer)


def establish_shared_secret(algorithm: str = "P-256") -> tuple[ECDHKeyPair, ECDHKeyPair, bytes]:
    """Create Alice/Bob key pairs and verify that both sides derive one secret."""

    alice = generate_keypair(algorithm)
    bob = generate_keypair(algorithm)
    alice_secret = derive_shared_secret(alice.private_key, bob.public_key, alice.algorithm)
    bob_secret = derive_shared_secret(bob.private_key, alice.public_key, bob.algorithm)
    if alice_secret != bob_secret:
        raise RuntimeError("ECDH invariant failed: Alice and Bob derived different secrets.")
    return alice, bob, alice_secret


def key_sizes(algorithm: str = "P-256") -> dict[str, int]:
    """Return the serialized key and raw-secret sizes used by this module."""

    normalized = _normalize_algorithm(algorithm)
    if normalized == "P-256":
        return {"private_key": 32, "public_key": 33, "shared_secret": 32}
    return {"private_key": 32, "public_key": 32, "shared_secret": 32}


__all__ = [
    "ECDHKeyPair",
    "derive_shared_secret",
    "establish_shared_secret",
    "generate_keypair",
    "key_sizes",
]
