import unittest

import kdf


class HKDFTests(unittest.TestCase):
    def test_rfc5869_sha256_case_1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        prk = kdf.hkdf_extract(salt, ikm)
        self.assertEqual(kdf.hkdf_expand(prk, info, 42), expected)

    def test_transcript_framing_is_unambiguous(self) -> None:
        self.assertNotEqual(kdf.transcript_hash(b"ab", b"c"), kdf.transcript_hash(b"a", b"bc"))

    def test_hybrid_output_is_32_bytes_and_binds_both_secrets(self) -> None:
        salt = kdf.transcript_hash(b"public-context")
        key1 = kdf.derive_session_key(b"A" * 32, b"B" * 32, salt=salt)
        key2 = kdf.derive_session_key(b"C" * 32, b"B" * 32, salt=salt)
        key3 = kdf.derive_session_key(b"A" * 32, b"D" * 32, salt=salt)
        self.assertEqual(len(key1), 32)
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)


if __name__ == "__main__":
    unittest.main()
