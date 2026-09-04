import unittest

from classical_kex import derive_shared_secret, generate_keypair
from kdf import derive_session_key, transcript_hash
from ml_kem import MLKEM


class IntegrationTests(unittest.TestCase):
    def test_ecdh_to_hkdf_pipeline(self) -> None:
        alice = generate_keypair("P-256")
        bob = generate_keypair("P-256")
        alice_secret = derive_shared_secret(alice.private_key, bob.public_key, "P-256")
        bob_secret = derive_shared_secret(bob.private_key, alice.public_key, "P-256")
        salt = transcript_hash(alice.public_key, bob.public_key)
        alice_key = derive_session_key(alice_secret, salt=salt)
        bob_key = derive_session_key(bob_secret, salt=salt)
        self.assertEqual(alice_key, bob_key)
        self.assertEqual(len(alice_key), 32)

    def test_ml_kem_to_hkdf_pipeline_all_variants(self) -> None:
        for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
            kem = MLKEM(name)
            keypair = kem.keygen()
            encapsulation = kem.encapsulate(keypair.public_key)
            receiver_secret = kem.decapsulate(keypair.private_key, encapsulation.ciphertext)
            salt = transcript_hash(keypair.public_key, encapsulation.ciphertext)
            sender_key = derive_session_key(encapsulation.shared_secret, salt=salt)
            receiver_key = derive_session_key(receiver_secret, salt=salt)
            self.assertEqual(sender_key, receiver_key)
            self.assertEqual(len(sender_key), 32)


if __name__ == "__main__":
    unittest.main()
