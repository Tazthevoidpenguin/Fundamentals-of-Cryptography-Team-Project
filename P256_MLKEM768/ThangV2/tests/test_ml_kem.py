import unittest

import ml_kem


class MLKEM768Tests(unittest.TestCase):
    def test_only_mlkem768_sizes(self) -> None:
        self.assertEqual(
            ml_kem.sizes(),
            {
                "public_key": 1184,
                "private_key": 2400,
                "ciphertext": 1088,
                "shared_secret": 32,
            },
        )

    def test_round_trip(self) -> None:
        keypair = ml_kem.keygen(bytes(range(64)))
        encapsulation = ml_kem.encapsulate(keypair.public_key, bytes(range(32)))
        recovered = ml_kem.decapsulate(keypair.private_key, encapsulation.ciphertext)
        self.assertEqual(recovered, encapsulation.shared_secret)
        self.assertEqual(len(recovered), 32)
        self.assertEqual(len(keypair.public_key), 1184)
        self.assertEqual(len(keypair.private_key), 2400)
        self.assertEqual(len(encapsulation.ciphertext), 1088)

    def test_tampered_ciphertext_uses_implicit_rejection(self) -> None:
        keypair = ml_kem.keygen(bytes(range(64)))
        encapsulation = ml_kem.encapsulate(keypair.public_key, bytes(range(32)))
        tampered = bytearray(encapsulation.ciphertext)
        tampered[500] ^= 1
        rejected = ml_kem.decapsulate(keypair.private_key, bytes(tampered))
        self.assertEqual(len(rejected), 32)
        self.assertNotEqual(rejected, encapsulation.shared_secret)
        self.assertEqual(rejected, ml_kem.decapsulate(keypair.private_key, bytes(tampered)))

    def test_public_key_can_be_recovered_from_private_key(self) -> None:
        keypair = ml_kem.keygen(bytes(reversed(range(64))))
        self.assertEqual(ml_kem.public_from_private(keypair.private_key), keypair.public_key)


if __name__ == "__main__":
    unittest.main()
