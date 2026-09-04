import unittest

from kdf import derive_session_key, derive_session_keys, transcript_hash


class HKDFTests(unittest.TestCase):
    def test_rfc5869_sha256_test_case_1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(
            derive_session_key(ikm, salt=salt, info=info, length=42),
            expected,
        )

    def test_context_separation(self) -> None:
        secret = b"S" * 32
        salt = transcript_hash(b"alice", b"bob")
        first = derive_session_key(secret, salt=salt, info=b"context-A")
        second = derive_session_key(secret, salt=salt, info=b"context-B")
        self.assertNotEqual(first, second)

    def test_transcript_framing_is_unambiguous(self) -> None:
        self.assertNotEqual(transcript_hash(b"ab", b"c"), transcript_hash(b"a", b"bc"))

    def test_derived_roles_are_separate(self) -> None:
        keys = derive_session_keys(b"K" * 32, salt=transcript_hash(b"exchange"))
        self.assertEqual(len(keys.encryption_key), 32)
        self.assertEqual(len(keys.confirmation_key), 32)
        self.assertNotEqual(keys.encryption_key, keys.confirmation_key)

    def test_rejects_empty_inputs(self) -> None:
        with self.assertRaises(ValueError):
            derive_session_key(b"", salt=None)
        with self.assertRaises(ValueError):
            derive_session_key(b"secret", salt=None, info=b"")


if __name__ == "__main__":
    unittest.main()
