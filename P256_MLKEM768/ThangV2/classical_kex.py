"""Minimal, hand-written ECDH over NIST P-256.

This module intentionally uses only the Python standard library.  It implements
just the curve operations needed by the coursework hybrid KEX:

    ECDH-P256 + ML-KEM-768 -> HKDF-SHA256 -> 32-byte session key

It is educational code, not a constant-time production implementation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final, Optional

# NIST P-256 / secp256r1 domain parameters.
P: Final[int] = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A: Final[int] = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B: Final[int] = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N: Final[int] = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX: Final[int] = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY: Final[int] = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

Point = Optional[tuple[int, int]]
G: Final[tuple[int, int]] = (GX, GY)


@dataclass(frozen=True)
class P256KeyPair:
    """Serialized P-256 key pair.

    ``private_key`` is a 32-byte scalar. ``public_key`` is a 33-byte SEC1
    compressed point. Private material must remain local/in RAM only.
    """

    private_key: bytes
    public_key: bytes


def _inverse(value: int, modulus: int = P) -> int:
    value %= modulus
    if value == 0:
        raise ZeroDivisionError("Cannot invert zero modulo the field prime.")
    return pow(value, -1, modulus)


def _is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def _point_add(left: Point, right: Point) -> Point:
    """Add two P-256 points in affine coordinates."""

    if left is None:
        return right
    if right is None:
        return left
    if not _is_on_curve(left) or not _is_on_curve(right):
        raise ValueError("Point is not on P-256.")

    x1, y1 = left
    x2, y2 = right

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if left == right:
        if y1 == 0:
            return None
        slope = ((3 * x1 * x1 + A) * _inverse(2 * y1)) % P
    else:
        slope = ((y2 - y1) * _inverse(x2 - x1)) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    result = (x3, y3)
    if not _is_on_curve(result):
        raise AssertionError("P-256 point-addition invariant failed.")
    return result


def _scalar_mult(scalar: int, point: Point) -> Point:
    """Double-and-add scalar multiplication."""

    if point is None:
        return None
    if not _is_on_curve(point):
        raise ValueError("Point is not on P-256.")
    scalar = int(scalar)
    if scalar < 0:
        raise ValueError("Scalar multiplication requires a non-negative integer.")
    if scalar == 0:
        return None

    result: Point = None
    addend: Point = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _encode_public(point: Point) -> bytes:
    """Encode a point using 33-byte SEC1 compressed form."""

    if point is None or not _is_on_curve(point):
        raise ValueError("Cannot encode an invalid/infinite P-256 point.")
    x, y = point
    prefix = 0x02 | (y & 1)
    return bytes((prefix,)) + x.to_bytes(32, "big")


def _decode_public(public_key: bytes) -> tuple[int, int]:
    """Decode and validate a compressed SEC1 P-256 public key."""

    public_key = bytes(public_key)
    if len(public_key) != 33 or public_key[0] not in (0x02, 0x03):
        raise ValueError("P-256 public key must be a 33-byte compressed SEC1 point.")

    x = int.from_bytes(public_key[1:], "big")
    if x >= P:
        raise ValueError("P-256 public-key x-coordinate is out of range.")

    rhs = (pow(x, 3, P) + A * x + B) % P
    # P-256 prime is 3 mod 4, so sqrt(rhs) = rhs^((p+1)/4) mod p.
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        raise ValueError("Compressed public key does not represent a P-256 point.")
    if (y & 1) != (public_key[0] & 1):
        y = P - y

    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("Decoded public key is not on P-256.")
    # P-256 has cofactor 1. This check also rejects malformed subgroup points.
    if _scalar_mult(N, point) is not None:
        raise ValueError("Public key failed P-256 subgroup validation.")
    return point


def public_from_private(private_key: bytes) -> bytes:
    """Return the compressed public key for a 32-byte private scalar."""

    private_key = bytes(private_key)
    if len(private_key) != 32:
        raise ValueError("P-256 private key must be exactly 32 bytes.")
    scalar = int.from_bytes(private_key, "big")
    if not 1 <= scalar < N:
        raise ValueError("P-256 private scalar must satisfy 1 <= d < n.")
    point = _scalar_mult(scalar, G)
    return _encode_public(point)


def generate_keypair(private_scalar: int | None = None) -> P256KeyPair:
    """Generate one P-256 key pair.

    ``private_scalar`` is only a deterministic test hook. In normal use it is
    omitted and a scalar is sampled from the operating system CSPRNG.
    """

    if private_scalar is None:
        private_scalar = secrets.randbelow(N - 1) + 1
    if not 1 <= int(private_scalar) < N:
        raise ValueError("P-256 private scalar must satisfy 1 <= d < n.")
    private_key = int(private_scalar).to_bytes(32, "big")
    return P256KeyPair(private_key=private_key, public_key=public_from_private(private_key))


def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Compute the raw 32-byte ECDH x-coordinate shared secret."""

    private_key = bytes(private_key)
    if len(private_key) != 32:
        raise ValueError("P-256 private key must be exactly 32 bytes.")
    scalar = int.from_bytes(private_key, "big")
    if not 1 <= scalar < N:
        raise ValueError("P-256 private scalar must satisfy 1 <= d < n.")

    peer_point = _decode_public(peer_public_key)
    shared_point = _scalar_mult(scalar, peer_point)
    if shared_point is None:
        raise ValueError("ECDH produced the point at infinity.")
    return shared_point[0].to_bytes(32, "big")


__all__ = [
    "P256KeyPair",
    "derive_shared_secret",
    "generate_keypair",
    "public_from_private",
]
