"""Small end-to-end demo for the revised hybrid KEX contract."""

import hashlib

import hybrid_kex


def short_fp(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def main() -> None:
    receiver_ecdh, receiver_mlkem = hybrid_kex.generate_receiver_keys()

    sender = hybrid_kex.sender_establish(
        receiver_ecdh.public_key,
        receiver_mlkem.public_key,
    )

    plaintext = b"hello hybrid key exchange"
    header = hybrid_kex.make_package_header(
        sender,
        group_id="BTL",
        message_id="demo-001",
        filename="hello.txt",
        plaintext_size=len(plaintext),
        plaintext_hash=hashlib.sha256(plaintext).digest(),
    )

    receiver = hybrid_kex.receiver_establish(
        receiver_ecdh.private_key,
        receiver_mlkem.private_key,
        header,
    )

    print("Algorithm:", sender.algorithm_id)
    print("P-256 public key:", len(sender.sender_ecdh_public), "bytes")
    print("ML-KEM-768 public key:", len(sender.receiver_mlkem_public), "bytes")
    print("ML-KEM-768 ciphertext:", len(sender.mlkem_ciphertext), "bytes")
    print("Session key:", len(sender.session_key), "bytes")
    print("Sender/receiver key match:", sender.session_key == receiver.session_key)
    print("Session-key fingerprint:", short_fp(sender.session_key))
    print("AAD size:", len(header.to_aad()), "bytes")


if __name__ == "__main__":
    main()
