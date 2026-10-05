import unittest

import classical_kex


class P256Tests(unittest.TestCase):
    def test_private_scalar_one_maps_to_generator(self) -> None:
        keypair = classical_kex.generate_keypair(1)
        expected = bytes.fromhex(
            "03"
            "6b17d1f2e12c4247f8bce6e563a440f2"
            "77037d812deb33a0f4a13945d898c296"
        )
        self.assertEqual(keypair.public_key, expected)

    def test_two_sides_derive_same_secret(self) -> None:
        alice = classical_kex.generate_keypair(0x123456789ABCDEF)
        bob = classical_kex.generate_keypair(0xFEDCBA987654321)
        a = classical_kex.derive_shared_secret(alice.private_key, bob.public_key)
        b = classical_kex.derive_shared_secret(bob.private_key, alice.public_key)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_rejects_invalid_compressed_point(self) -> None:
        alice = classical_kex.generate_keypair(7)
        with self.assertRaises(ValueError):
            classical_kex.derive_shared_secret(alice.private_key, b"\x02" + b"\xff" * 32)

    def test_public_from_private_round_trip(self) -> None:
        keypair = classical_kex.generate_keypair(42)
        self.assertEqual(classical_kex.public_from_private(keypair.private_key), keypair.public_key)


if __name__ == "__main__":
    unittest.main()
