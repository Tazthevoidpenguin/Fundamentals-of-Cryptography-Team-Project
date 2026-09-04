"""Run the two CryptoShield key-establishment modes end to end."""

from __future__ import annotations

import hashlib

from classical_kex import derive_shared_secret, generate_keypair
from kdf import derive_session_key, transcript_hash
from ml_kem import MLKEM, available_variants


def fingerprint(data: bytes) -> str:
    """Return a short public fingerprint without printing secret key material."""

    return hashlib.sha256(data).hexdigest()[:16]


def demo_ecdh() -> None:
    alice = generate_keypair("P-256")
    bob = generate_keypair("P-256")
    alice_secret = derive_shared_secret(alice.private_key, bob.public_key, "P-256")
    bob_secret = derive_shared_secret(bob.private_key, alice.public_key, "P-256")
    salt = transcript_hash(alice.public_key, bob.public_key)
    alice_aes_key = derive_session_key(alice_secret, salt=salt)
    bob_aes_key = derive_session_key(bob_secret, salt=salt)

    print("[Classical Mode] ECDH P-256 -> HKDF-SHA-256")
    print(f"  Alice public key: {len(alice.public_key)} bytes")
    print(f"  Bob public key:   {len(bob.public_key)} bytes")
    print(f"  AES key match:    {alice_aes_key == bob_aes_key}")
    print(f"  AES key fingerprint: {fingerprint(alice_aes_key)}")


def demo_ml_kem() -> None:
    print("\n[Post-Quantum Mode] ML-KEM -> HKDF-SHA-256")
    for variant in available_variants():
        kem = MLKEM(variant)
        receiver = kem.keygen()
        sender = kem.encapsulate(receiver.public_key)
        receiver_secret = kem.decapsulate(receiver.private_key, sender.ciphertext)
        salt = transcript_hash(receiver.public_key, sender.ciphertext)
        sender_aes_key = derive_session_key(sender.shared_secret, salt=salt)
        receiver_aes_key = derive_session_key(receiver_secret, salt=salt)
        sizes = kem.sizes()
        print(
            f"  {variant}: pk={sizes['public_key']} B, ct={sizes['ciphertext']} B, "
            f"AES key match={sender_aes_key == receiver_aes_key}, "
            f"fingerprint={fingerprint(sender_aes_key)}"
        )


if __name__ == "__main__":
    demo_ecdh()
    demo_ml_kem()
