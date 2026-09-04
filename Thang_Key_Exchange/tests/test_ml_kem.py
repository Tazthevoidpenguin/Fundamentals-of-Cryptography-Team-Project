import unittest

from ml_kem import (
    MLKEM,
    PARAMETER_SETS,
    _ntt,
    _inverse_ntt,
    _prf,
    _sample_ntt,
    _sample_poly_cbd,
)


class MLKEMTests(unittest.TestCase):
    def test_fips203_parameter_sizes(self) -> None:
        expected = {
            "ML-KEM-512": (800, 1632, 768, 32),
            "ML-KEM-768": (1184, 2400, 1088, 32),
            "ML-KEM-1024": (1568, 3168, 1568, 32),
        }
        for name, sizes in expected.items():
            params = PARAMETER_SETS[name]
            self.assertEqual(
                (
                    params.public_key_bytes,
                    params.private_key_bytes,
                    params.ciphertext_bytes,
                    params.shared_secret_bytes,
                ),
                sizes,
            )

    def test_nist_acvp_keygen_spot_check_ml_kem_512(self) -> None:
        # NIST ACVP FIPS 203 keyGen, tgId=1, tcId=1.
        d = bytes.fromhex("47B893474672BA92E4B12EE44FB32953AF8E8503B5FB471D1614FB8A021A660A")
        z = bytes.fromhex("1F8CB39E9E30BC458A0DC5408884B1187FB217018DF760FA57317703B844A0A9")
        keypair = MLKEM("512").keygen(d + z)
        self.assertEqual(
            keypair.public_key[:32].hex().upper(),
            "28266A088B3482439BCA01AFB7CA5C6136A979B5159985A9484B36B679A5F7B9",
        )
        self.assertEqual(
            keypair.public_key[-32:].hex().upper(),
            "3692611D2E34D57B36CC4B2CD3B31FF485C6684D408B972E0D5CA7D2224AAE4E",
        )
        self.assertEqual(
            keypair.private_key[:32].hex().upper(),
            "89C31D05611AAAB258F78BC2DE0A80D5914BF80C376A990D33CB97F4F2077CE1",
        )
        self.assertEqual(keypair.private_key[-32:], z)

    def test_sampling_and_ntt_intermediate_values(self) -> None:
        rho = bytes.fromhex("b1720e4ed5ac0add457f573a041465bcbd7ca4e1d7d53eaadeda511962a36eb0")
        sampled = _sample_ntt(rho + b"\x00\x00")
        self.assertEqual(
            sampled[:16],
            [2322, 479, 3, 783, 2874, 1746, 2961, 2018, 1000, 667, 1686, 115, 1257, 268, 1040, 2914],
        )

        sigma = bytes.fromhex("176c5e5bdef7f0b03349110742125810116450aa6ed6a02a87a8c04cb508d6fa")
        cbd = _sample_poly_cbd(_prf(sigma, 0, 3), 3)
        self.assertEqual(cbd[:16], [1, 0, 3328, 1, 3328, 0, 0, 2, 0, 3328, 1, 0, 2, 2, 0, 3328])
        transformed = _ntt(cbd)
        self.assertEqual(
            transformed[:16],
            [1837, 3137, 1722, 738, 222, 252, 512, 591, 630, 2953, 635, 1388, 3151, 1951, 272, 319],
        )
        self.assertEqual(_inverse_ntt(transformed), cbd)

    def test_round_trip_all_variants(self) -> None:
        for offset, name in enumerate(("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")):
            kem = MLKEM(name)
            seed = bytes((index + offset) % 256 for index in range(64))
            randomness = bytes((255 - index - offset) % 256 for index in range(32))
            keypair = kem.keygen(seed)
            encapsulation = kem.encapsulate(keypair.public_key, randomness)
            recovered = kem.decapsulate(keypair.private_key, encapsulation.ciphertext)
            self.assertEqual(recovered, encapsulation.shared_secret)
            self.assertEqual(len(recovered), 32)
            self.assertEqual(len(keypair.public_key), kem.sizes()["public_key"])
            self.assertEqual(len(keypair.private_key), kem.sizes()["private_key"])
            self.assertEqual(len(encapsulation.ciphertext), kem.sizes()["ciphertext"])

    def test_tampered_ciphertext_uses_implicit_rejection(self) -> None:
        kem = MLKEM("ML-KEM-768")
        keypair = kem.keygen(bytes(range(64)))
        encapsulation = kem.encapsulate(keypair.public_key, bytes(range(32)))
        tampered = bytearray(encapsulation.ciphertext)
        tampered[len(tampered) // 2] ^= 0x01
        rejected_secret = kem.decapsulate(keypair.private_key, bytes(tampered))
        self.assertEqual(len(rejected_secret), 32)
        self.assertNotEqual(rejected_secret, encapsulation.shared_secret)
        self.assertEqual(rejected_secret, kem.decapsulate(keypair.private_key, bytes(tampered)))

    def test_rejects_non_canonical_public_key(self) -> None:
        kem = MLKEM("ML-KEM-512")
        keypair = kem.keygen(bytes(range(64)))
        invalid = bytearray(keypair.public_key)
        # Encode q=3329 (0xD01) into the first 12-bit coefficient.
        invalid[0] = 0x01
        invalid[1] = (invalid[1] & 0xF0) | 0x0D
        with self.assertRaises(ValueError):
            kem.encapsulate(bytes(invalid), bytes(range(32)))

    def test_rejects_private_key_with_modified_embedded_hash(self) -> None:
        kem = MLKEM("ML-KEM-512")
        keypair = kem.keygen(bytes(range(64)))
        encapsulation = kem.encapsulate(keypair.public_key, bytes(range(32)))
        invalid = bytearray(keypair.private_key)
        hash_offset = 384 * kem.params.k + kem.params.public_key_bytes
        invalid[hash_offset] ^= 0x01
        with self.assertRaises(ValueError):
            kem.decapsulate(bytes(invalid), encapsulation.ciphertext)


if __name__ == "__main__":
    unittest.main()
