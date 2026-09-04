import unittest

from classical_kex import derive_shared_secret, generate_keypair, key_sizes


class ClassicalKEXTests(unittest.TestCase):
    def test_p256_both_sides_derive_same_secret(self) -> None:
        alice = generate_keypair("P-256")
        bob = generate_keypair("secp256r1")
        alice_secret = derive_shared_secret(alice.private_key, bob.public_key, "P-256")
        bob_secret = derive_shared_secret(bob.private_key, alice.public_key, "P-256")
        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(len(alice_secret), 32)
        self.assertEqual(len(alice.public_key), 33)

    def test_x25519_both_sides_derive_same_secret(self) -> None:
        alice = generate_keypair("X25519")
        bob = generate_keypair("X25519")
        alice_secret = derive_shared_secret(alice.private_key, bob.public_key, "X25519")
        bob_secret = derive_shared_secret(bob.private_key, alice.public_key, "X25519")
        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(len(alice_secret), 32)
        self.assertEqual(len(alice.public_key), 32)

    def test_rejects_invalid_p256_point(self) -> None:
        keypair = generate_keypair("P-256")
        with self.assertRaises(ValueError):
            derive_shared_secret(keypair.private_key, b"\x04" + b"\x00" * 64, "P-256")

    def test_declared_key_sizes(self) -> None:
        self.assertEqual(key_sizes("P-256"), {"private_key": 32, "public_key": 33, "shared_secret": 32})
        self.assertEqual(key_sizes("X25519"), {"private_key": 32, "public_key": 32, "shared_secret": 32})


if __name__ == "__main__":
    unittest.main()
