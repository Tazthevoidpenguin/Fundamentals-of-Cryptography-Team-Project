import hashlib
import unittest
from dataclasses import replace

import hybrid_kex


class HybridKexTests(unittest.TestCase):
    def _make_exchange(self):
        receiver_ecdh, receiver_mlkem = hybrid_kex.generate_receiver_keys(
            ecdh_private_scalar=123456789,
            mlkem_seed=bytes(range(64)),
        )
        sender = hybrid_kex.sender_establish(
            receiver_ecdh.public_key,
            receiver_mlkem.public_key,
            session_id=bytes(range(16)),
            sender_ecdh_private_scalar=987654321,
            mlkem_randomness=bytes(range(32)),
        )
        header = hybrid_kex.make_package_header(
            sender,
            group_id="BTL-NHOM",
            message_id="msg-0001",
            filename="demo.txt",
            plaintext_size=5,
            plaintext_hash=hashlib.sha256(b"hello").digest(),
        )
        return receiver_ecdh, receiver_mlkem, sender, header

    def test_sender_receiver_get_same_32_byte_session_key(self) -> None:
        receiver_ecdh, receiver_mlkem, sender, header = self._make_exchange()
        receiver = hybrid_kex.receiver_establish(
            receiver_ecdh.private_key,
            receiver_mlkem.private_key,
            header,
        )
        self.assertEqual(sender.algorithm_id, "P256-ML768")
        self.assertEqual(sender.session_key, receiver.session_key)
        self.assertEqual(len(sender.session_key), 32)
        self.assertEqual(sender.transcript_hash, receiver.transcript_hash)

    def test_package_header_aad_contains_no_session_key(self) -> None:
        _, _, sender, header = self._make_exchange()
        aad = header.to_aad()
        self.assertNotIn(sender.session_key, aad)
        self.assertIn(sender.session_id, aad)
        self.assertIn(sender.mlkem_ciphertext[:32], aad)

    def test_header_tampering_breaks_transcript_check(self) -> None:
        receiver_ecdh, receiver_mlkem, _, header = self._make_exchange()
        bad = replace(header, transcript_hash=b"\x00" * 32)
        with self.assertRaisesRegex(ValueError, "transcript hash"):
            hybrid_kex.receiver_establish(
                receiver_ecdh.private_key,
                receiver_mlkem.private_key,
                bad,
            )

    def test_wrong_receiver_private_key_is_rejected(self) -> None:
        _, receiver_mlkem, _, header = self._make_exchange()
        wrong_ecdh, _ = hybrid_kex.generate_receiver_keys(
            ecdh_private_scalar=222222222,
            mlkem_seed=bytes(range(64)),
        )
        with self.assertRaisesRegex(ValueError, "ECDH public key"):
            hybrid_kex.receiver_establish(
                wrong_ecdh.private_key,
                receiver_mlkem.private_key,
                header,
            )


if __name__ == "__main__":
    unittest.main()
