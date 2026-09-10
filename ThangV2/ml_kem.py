"""Hand-written educational ML-KEM-768 implementation (FIPS 203 structure).

Only ML-KEM-768 is kept because the revised coursework design uses one hybrid
suite: P-256 + ML-KEM-768. The implementation uses only Python's standard
library (SHA-3/SHAKE, HMAC and OS randomness).

Security notice: this is readable coursework code, not constant-time or
FIPS-validated production cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final, Sequence

Q: Final[int] = 3329
N: Final[int] = 256
ZETA: Final[int] = 17
SHARED_SECRET_SIZE: Final[int] = 32


@dataclass(frozen=True)
class MLKEMParameters:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    public_key_bytes: int
    private_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int = SHARED_SECRET_SIZE


PARAMS: Final[MLKEMParameters] = MLKEMParameters(
    name="ML-KEM-768",
    k=3,
    eta1=2,
    eta2=2,
    du=10,
    dv=4,
    public_key_bytes=1184,
    private_key_bytes=2400,
    ciphertext_bytes=1088,
)

@dataclass(frozen=True)
class MLKEMKeyPair:
    """Serialized ML-KEM encapsulation and decapsulation keys."""

    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class MLKEMEncapsulation:
    """Ciphertext and the encapsulator's 32-byte shared secret."""

    ciphertext: bytes
    shared_secret: bytes


def _h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _g(data: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:]


def _j(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)


def _prf(seed: bytes, nonce: int, eta: int) -> bytes:
    if len(seed) != 32:
        raise ValueError("PRF seed must be exactly 32 bytes.")
    if not 0 <= nonce <= 255:
        raise ValueError("PRF nonce must fit in one byte.")
    return hashlib.shake_256(seed + bytes((nonce,))).digest(64 * eta)


def _bit_reverse_7(value: int) -> int:
    result = 0
    for _ in range(7):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _ntt(poly: Sequence[int]) -> list[int]:
    """Compute the FIPS 203 NTT representation of a polynomial."""

    if len(poly) != N:
        raise ValueError(f"Polynomial must contain {N} coefficients.")
    out = [value % Q for value in poly]
    zeta_index = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = pow(ZETA, _bit_reverse_7(zeta_index), Q)
            zeta_index += 1
            for index in range(start, start + length):
                temp = (zeta * out[index + length]) % Q
                out[index + length] = (out[index] - temp) % Q
                out[index] = (out[index] + temp) % Q
        length //= 2
    if zeta_index != 128:  # Defensive invariant.
        raise AssertionError("Unexpected NTT twiddle-factor count.")
    return out


def _inverse_ntt(poly_hat: Sequence[int]) -> list[int]:
    """Convert an NTT representation back to the standard representation."""

    if len(poly_hat) != N:
        raise ValueError(f"Polynomial must contain {N} coefficients.")
    out = [value % Q for value in poly_hat]
    zeta_index = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = pow(ZETA, _bit_reverse_7(zeta_index), Q)
            zeta_index -= 1
            for index in range(start, start + length):
                temp = out[index]
                out[index] = (temp + out[index + length]) % Q
                out[index + length] = (zeta * (out[index + length] - temp)) % Q
        length *= 2
    if zeta_index != 0:
        raise AssertionError("Unexpected inverse-NTT twiddle-factor count.")
    # 3303 is 128^(-1) modulo q, as specified by FIPS 203.
    return [(value * 3303) % Q for value in out]


def _multiply_ntts(left: Sequence[int], right: Sequence[int]) -> list[int]:
    """Multiply two polynomials represented in the NTT domain."""

    if len(left) != N or len(right) != N:
        raise ValueError(f"Both polynomials must contain {N} coefficients.")
    result = [0] * N
    for index in range(128):
        even = 2 * index
        gamma = pow(ZETA, 2 * _bit_reverse_7(index) + 1, Q)
        a0, a1 = left[even] % Q, left[even + 1] % Q
        b0, b1 = right[even] % Q, right[even + 1] % Q
        result[even] = (a0 * b0 + a1 * b1 * gamma) % Q
        result[even + 1] = (a0 * b1 + a1 * b0) % Q
    return result


def _poly_add(left: Sequence[int], right: Sequence[int]) -> list[int]:
    if len(left) != N or len(right) != N:
        raise ValueError(f"Both polynomials must contain {N} coefficients.")
    return [(a + b) % Q for a, b in zip(left, right)]


def _poly_sub(left: Sequence[int], right: Sequence[int]) -> list[int]:
    if len(left) != N or len(right) != N:
        raise ValueError(f"Both polynomials must contain {N} coefficients.")
    return [(a - b) % Q for a, b in zip(left, right)]


def _sample_ntt(seed: bytes) -> list[int]:
    """Sample a uniformly random NTT polynomial using SHAKE128 rejection sampling."""

    if len(seed) != 34:
        raise ValueError("SampleNTT input must be 34 bytes (rho || i || j).")

    # SHAKE is conceptually an unbounded XOF. Request increasingly larger
    # prefixes until 256 accepted coefficients are available.
    output_length = 3 * N
    while True:
        stream = hashlib.shake_128(seed).digest(output_length)
        result: list[int] = []
        for offset in range(0, len(stream) - 2, 3):
            byte0, byte1, byte2 = stream[offset : offset + 3]
            candidate1 = byte0 + 256 * (byte1 & 0x0F)
            candidate2 = (byte1 >> 4) + 16 * byte2
            if candidate1 < Q:
                result.append(candidate1)
                if len(result) == N:
                    return result
            if candidate2 < Q:
                result.append(candidate2)
                if len(result) == N:
                    return result
        output_length *= 2


def _sample_poly_cbd(random_bytes: bytes, eta: int) -> list[int]:
    """Sample a polynomial from the centered binomial distribution CBD_eta."""

    expected_length = 64 * eta
    if len(random_bytes) != expected_length:
        raise ValueError(f"CBD_eta input must be exactly {expected_length} bytes.")
    if eta not in (2, 3):
        raise ValueError("This ML-KEM implementation supports eta values 2 and 3 only.")

    bits = int.from_bytes(random_bytes, "little")
    half_mask = (1 << eta) - 1
    coefficient_mask = (1 << (2 * eta)) - 1
    result: list[int] = []
    for index in range(N):
        window = (bits >> (2 * eta * index)) & coefficient_mask
        low_weight = (window & half_mask).bit_count()
        high_weight = ((window >> eta) & half_mask).bit_count()
        result.append((low_weight - high_weight) % Q)
    return result


def _byte_encode(values: Sequence[int], width: int) -> bytes:
    """FIPS 203 ByteEncode_d using little-endian bit packing."""

    if width <= 0 or width > 12:
        raise ValueError("Encoding width must be between 1 and 12 bits.")
    modulus = Q if width == 12 else 1 << width
    accumulator = 0
    bit_count = 0
    output = bytearray()
    for value in values:
        if not 0 <= int(value) < modulus:
            raise ValueError(f"Coefficient {value!r} is out of range for width {width}.")
        accumulator |= int(value) << bit_count
        bit_count += width
        while bit_count >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bit_count -= 8
    if bit_count:
        output.append(accumulator & 0xFF)
    expected = (len(values) * width + 7) // 8
    if len(output) != expected:
        raise AssertionError("Unexpected ByteEncode output length.")
    return bytes(output)


def _byte_decode(encoded: bytes, width: int, count: int = N) -> list[int]:
    """FIPS 203 ByteDecode_d using little-endian bit unpacking."""

    if width <= 0 or width > 12:
        raise ValueError("Decoding width must be between 1 and 12 bits.")
    expected = (count * width + 7) // 8
    if len(encoded) != expected:
        raise ValueError(f"Expected {expected} encoded bytes, received {len(encoded)}.")
    mask = (1 << width) - 1
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    byte_index = 0
    while len(result) < count:
        while bit_count < width:
            accumulator |= encoded[byte_index] << bit_count
            bit_count += 8
            byte_index += 1
        result.append(accumulator & mask)
        accumulator >>= width
        bit_count -= width
    return result


def _compress(coefficient: int, width: int) -> int:
    """Compress a Z_q coefficient into ``width`` bits."""

    coefficient %= Q
    return ((coefficient * (1 << width) + Q // 2) // Q) & ((1 << width) - 1)


def _decompress(value: int, width: int) -> int:
    """Decompress a ``width``-bit value into Z_q."""

    if not 0 <= value < (1 << width):
        raise ValueError(f"Compressed value {value!r} does not fit in {width} bits.")
    return (value * Q + (1 << (width - 1))) >> width


def _encode_poly_vector(polynomials: Sequence[Sequence[int]], width: int) -> bytes:
    return b"".join(_byte_encode(poly, width) for poly in polynomials)


def _decode_poly_vector(encoded: bytes, width: int, count: int) -> list[list[int]]:
    bytes_per_poly = N * width // 8
    expected = count * bytes_per_poly
    if len(encoded) != expected:
        raise ValueError(f"Expected {expected} bytes for {count} polynomials, got {len(encoded)}.")
    return [
        _byte_decode(encoded[index * bytes_per_poly : (index + 1) * bytes_per_poly], width)
        for index in range(count)
    ]


def _compress_poly(poly: Sequence[int], width: int) -> list[int]:
    if len(poly) != N:
        raise ValueError(f"Polynomial must contain {N} coefficients.")
    return [_compress(value, width) for value in poly]


def _decompress_poly(poly: Sequence[int], width: int) -> list[int]:
    if len(poly) != N:
        raise ValueError(f"Polynomial must contain {N} coefficients.")
    return [_decompress(value, width) for value in poly]


def _validate_encapsulation_key(public_key: bytes, params: MLKEMParameters) -> None:
    if len(public_key) != params.public_key_bytes:
        raise ValueError(
            f"{params.name} public key must be {params.public_key_bytes} bytes; "
            f"received {len(public_key)}."
        )
    encoded_t = public_key[: 384 * params.k]
    decoded_t = _decode_poly_vector(encoded_t, 12, params.k)
    # ByteDecode_12 can represent values through 4095; ML-KEM public-key
    # coefficients must have canonical values in [0, q-1].
    if any(value >= Q for poly in decoded_t for value in poly):
        raise ValueError("ML-KEM public key failed the modulus/canonical-encoding check.")


def _k_pke_keygen(params: MLKEMParameters, seed_d: bytes) -> tuple[bytes, bytes]:
    if len(seed_d) != 32:
        raise ValueError("K-PKE key-generation seed must be 32 bytes.")

    rho, sigma = _g(seed_d + bytes((params.k,)))
    matrix_hat = [
        [_sample_ntt(rho + bytes((column, row))) for column in range(params.k)]
        for row in range(params.k)
    ]

    nonce = 0
    secret = []
    for _ in range(params.k):
        secret.append(_sample_poly_cbd(_prf(sigma, nonce, params.eta1), params.eta1))
        nonce += 1
    error = []
    for _ in range(params.k):
        error.append(_sample_poly_cbd(_prf(sigma, nonce, params.eta1), params.eta1))
        nonce += 1

    secret_hat = [_ntt(poly) for poly in secret]
    error_hat = [_ntt(poly) for poly in error]

    t_hat: list[list[int]] = []
    for row in range(params.k):
        accumulated = [0] * N
        for column in range(params.k):
            accumulated = _poly_add(
                accumulated,
                _multiply_ntts(matrix_hat[row][column], secret_hat[column]),
            )
        t_hat.append(_poly_add(accumulated, error_hat[row]))

    encryption_key = _encode_poly_vector(t_hat, 12) + rho
    decryption_key = _encode_poly_vector(secret_hat, 12)
    return encryption_key, decryption_key


def _k_pke_encrypt(
    params: MLKEMParameters,
    public_key: bytes,
    message: bytes,
    randomness: bytes,
) -> bytes:
    if len(message) != 32:
        raise ValueError("K-PKE message must be exactly 32 bytes.")
    if len(randomness) != 32:
        raise ValueError("K-PKE encryption randomness must be exactly 32 bytes.")
    _validate_encapsulation_key(public_key, params)

    encoded_t_length = 384 * params.k
    t_hat = _decode_poly_vector(public_key[:encoded_t_length], 12, params.k)
    rho = public_key[encoded_t_length:]

    # Generate the transpose directly.  A^T[i,j] = SampleNTT(rho || i || j).
    transposed_matrix_hat = [
        [_sample_ntt(rho + bytes((row, column))) for column in range(params.k)]
        for row in range(params.k)
    ]

    nonce = 0
    r = []
    for _ in range(params.k):
        r.append(_sample_poly_cbd(_prf(randomness, nonce, params.eta1), params.eta1))
        nonce += 1
    e1 = []
    for _ in range(params.k):
        e1.append(_sample_poly_cbd(_prf(randomness, nonce, params.eta2), params.eta2))
        nonce += 1
    e2 = _sample_poly_cbd(_prf(randomness, nonce, params.eta2), params.eta2)

    r_hat = [_ntt(poly) for poly in r]
    u: list[list[int]] = []
    for row in range(params.k):
        accumulated = [0] * N
        for column in range(params.k):
            accumulated = _poly_add(
                accumulated,
                _multiply_ntts(transposed_matrix_hat[row][column], r_hat[column]),
            )
        u.append(_poly_add(_inverse_ntt(accumulated), e1[row]))

    accumulated_v = [0] * N
    for index in range(params.k):
        accumulated_v = _poly_add(
            accumulated_v,
            _multiply_ntts(t_hat[index], r_hat[index]),
        )
    message_poly = _decompress_poly(_byte_decode(message, 1), 1)
    v = _poly_add(_poly_add(_inverse_ntt(accumulated_v), e2), message_poly)

    c1 = _encode_poly_vector([_compress_poly(poly, params.du) for poly in u], params.du)
    c2 = _byte_encode(_compress_poly(v, params.dv), params.dv)
    ciphertext = c1 + c2
    if len(ciphertext) != params.ciphertext_bytes:
        raise AssertionError("Unexpected K-PKE ciphertext length.")
    return ciphertext


def _k_pke_decrypt(params: MLKEMParameters, decryption_key: bytes, ciphertext: bytes) -> bytes:
    expected_dk_length = 384 * params.k
    if len(decryption_key) != expected_dk_length:
        raise ValueError(
            f"K-PKE decryption key must be {expected_dk_length} bytes; got {len(decryption_key)}."
        )
    if len(ciphertext) != params.ciphertext_bytes:
        raise ValueError(
            f"{params.name} ciphertext must be {params.ciphertext_bytes} bytes; "
            f"received {len(ciphertext)}."
        )

    c1_length = 32 * params.du * params.k
    encoded_u = ciphertext[:c1_length]
    encoded_v = ciphertext[c1_length:]

    compressed_u = _decode_poly_vector(encoded_u, params.du, params.k)
    u = [_decompress_poly(poly, params.du) for poly in compressed_u]
    v = _decompress_poly(_byte_decode(encoded_v, params.dv), params.dv)
    secret_hat = _decode_poly_vector(decryption_key, 12, params.k)

    u_hat = [_ntt(poly) for poly in u]
    accumulated = [0] * N
    for index in range(params.k):
        accumulated = _poly_add(
            accumulated,
            _multiply_ntts(secret_hat[index], u_hat[index]),
        )
    recovered = _poly_sub(v, _inverse_ntt(accumulated))
    return _byte_encode(_compress_poly(recovered, 1), 1)


def _ml_kem_keygen_internal(params: MLKEMParameters, seed_d: bytes, seed_z: bytes) -> MLKEMKeyPair:
    if len(seed_d) != 32 or len(seed_z) != 32:
        raise ValueError("ML-KEM key generation requires two independent 32-byte seeds.")
    public_key, pke_private_key = _k_pke_keygen(params, seed_d)
    private_key = pke_private_key + public_key + _h(public_key) + seed_z
    if len(public_key) != params.public_key_bytes or len(private_key) != params.private_key_bytes:
        raise AssertionError("Unexpected ML-KEM key length.")
    return MLKEMKeyPair(public_key=public_key, private_key=private_key)


def _ml_kem_encaps_internal(
    params: MLKEMParameters,
    public_key: bytes,
    message_randomness: bytes,
) -> MLKEMEncapsulation:
    if len(message_randomness) != 32:
        raise ValueError("ML-KEM encapsulation randomness must be 32 bytes.")
    _validate_encapsulation_key(public_key, params)
    shared_secret, encryption_randomness = _g(message_randomness + _h(public_key))
    ciphertext = _k_pke_encrypt(params, public_key, message_randomness, encryption_randomness)
    return MLKEMEncapsulation(ciphertext=ciphertext, shared_secret=shared_secret)


def _ml_kem_decaps_internal(params: MLKEMParameters, private_key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) != params.ciphertext_bytes:
        raise ValueError(
            f"{params.name} ciphertext must be {params.ciphertext_bytes} bytes; "
            f"received {len(ciphertext)}."
        )
    if len(private_key) != params.private_key_bytes:
        raise ValueError(
            f"{params.name} private key must be {params.private_key_bytes} bytes; "
            f"received {len(private_key)}."
        )

    pke_private_length = 384 * params.k
    public_key_length = params.public_key_bytes
    pke_private_key = private_key[:pke_private_length]
    public_key = private_key[pke_private_length : pke_private_length + public_key_length]
    stored_public_key_hash = private_key[
        pke_private_length + public_key_length : pke_private_length + public_key_length + 32
    ]
    implicit_rejection_seed = private_key[-32:]

    if not hmac.compare_digest(_h(public_key), stored_public_key_hash):
        raise ValueError("ML-KEM private key failed its embedded public-key hash check.")

    recovered_message = _k_pke_decrypt(params, pke_private_key, ciphertext)
    candidate_secret, encryption_randomness = _g(recovered_message + stored_public_key_hash)
    rejection_secret = _j(implicit_rejection_seed + ciphertext)
    reconstructed_ciphertext = _k_pke_encrypt(
        params,
        public_key,
        recovered_message,
        encryption_randomness,
    )

    # Python cannot promise constant-time object handling. compare_digest is
    # nevertheless used to avoid an ordinary early-exit byte comparison.
    return candidate_secret if hmac.compare_digest(ciphertext, reconstructed_ciphertext) else rejection_secret



def sizes() -> dict[str, int]:
    """Serialized object sizes for ML-KEM-768, in bytes."""

    return {
        "public_key": PARAMS.public_key_bytes,
        "private_key": PARAMS.private_key_bytes,
        "ciphertext": PARAMS.ciphertext_bytes,
        "shared_secret": PARAMS.shared_secret_bytes,
    }


def keygen(seed: bytes | None = None) -> MLKEMKeyPair:
    """Generate an ML-KEM-768 key pair.

    ``seed`` is an optional 64-byte deterministic test hook (d || z). Omit it
    in normal use so the operating-system CSPRNG is used.
    """

    if seed is None:
        seed = secrets.token_bytes(64)
    seed = bytes(seed)
    if len(seed) != 64:
        raise ValueError("ML-KEM-768 keygen seed must be exactly 64 bytes (d || z).")
    return _ml_kem_keygen_internal(PARAMS, seed[:32], seed[32:])


def encapsulate(public_key: bytes, randomness: bytes | None = None) -> MLKEMEncapsulation:
    """Encapsulate to an ML-KEM-768 public key."""

    if randomness is None:
        randomness = secrets.token_bytes(32)
    randomness = bytes(randomness)
    if len(randomness) != 32:
        raise ValueError("ML-KEM-768 encapsulation randomness must be exactly 32 bytes.")
    return _ml_kem_encaps_internal(PARAMS, bytes(public_key), randomness)


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an ML-KEM-768 ciphertext using implicit rejection."""

    return _ml_kem_decaps_internal(PARAMS, bytes(private_key), bytes(ciphertext))


def public_from_private(private_key: bytes) -> bytes:
    """Extract the embedded public key from a serialized ML-KEM-768 private key."""

    private_key = bytes(private_key)
    if len(private_key) != PARAMS.private_key_bytes:
        raise ValueError(f"ML-KEM-768 private key must be {PARAMS.private_key_bytes} bytes.")
    pke_private_length = 384 * PARAMS.k
    start = pke_private_length
    end = start + PARAMS.public_key_bytes
    public_key = private_key[start:end]
    stored_hash = private_key[end:end + 32]
    if not hmac.compare_digest(_h(public_key), stored_hash):
        raise ValueError("ML-KEM-768 private key failed its embedded public-key hash check.")
    return public_key


__all__ = [
    "MLKEMEncapsulation",
    "MLKEMKeyPair",
    "PARAMS",
    "decapsulate",
    "encapsulate",
    "keygen",
    "public_from_private",
    "sizes",
]
