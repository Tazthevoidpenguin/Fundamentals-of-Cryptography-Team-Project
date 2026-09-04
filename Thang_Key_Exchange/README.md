# Phần Key Exchange của Thắng — CryptoShield

Thư mục này hoàn thành phần được giao trong đề cương:

- `classical_kex.py`: ECDH truyền thống, hỗ trợ P-256 và X25519; mặc định P-256.
- `ml_kem.py`: ML-KEM-512/768/1024 theo cấu trúc FIPS 203, viết thuần Python để phục vụ học tập và thực nghiệm.
- `kdf.py`: HKDF-SHA-256, dẫn xuất khóa AES-256 từ shared secret và băm transcript.
- `demo_key_exchange.py`: chạy hai pipeline ECDH/ML-KEM → shared secret → HKDF.
- `benchmark_kex.py`: đo KeyGen, Key Agreement, Encaps và Decaps; xuất CSV.
- `tests/`: kiểm thử thuật toán, kích thước, NIST ACVP spot-check, RFC 5869, implicit rejection và tích hợp.
- `Tai_lieu_ly_thuyet_Topic_9.docx`: phần lý thuyết có thể dùng trong báo cáo/thuyết trình.
- `diagrams/`: 3 sơ đồ ở cả định dạng SVG và PNG (pipeline tổng quan, luồng ECDH, luồng ML-KEM).
- `TEST_RESULTS.txt`: biên bản kiểm thử cuối cùng của gói bàn giao.

## 1. Cài đặt

Yêu cầu Python 3.10 trở lên.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 2. Chạy kiểm thử

```bash
python -m unittest discover -s tests -v
```

## 3. Chạy demo

```bash
python demo_key_exchange.py
```

Demo không in shared secret hoặc khóa AES thô; chỉ in kích thước và fingerprint ngắn.

## 4. Chạy benchmark

```bash
python benchmark_kex.py --repeats 30 --output results/benchmark_kex.csv
```

Mỗi phép đo nên lặp lại nhiều lần. Khi đưa số liệu vào báo cáo, cần ghi rõ CPU, RAM, hệ điều hành, phiên bản Python/thư viện và giải thích rằng ML-KEM trong thư mục này là bản tham chiếu thuần Python, không thể so trực tiếp tốc độ tuyệt đối với thư viện native tối ưu.

## 5. Hợp đồng tích hợp với phần AES-GCM

### Classical Mode

```python
from classical_kex import generate_keypair, derive_shared_secret
from kdf import transcript_hash, derive_session_key

alice = generate_keypair("P-256")
bob = generate_keypair("P-256")

alice_ss = derive_shared_secret(alice.private_key, bob.public_key, "P-256")
bob_ss = derive_shared_secret(bob.private_key, alice.public_key, "P-256")

salt = transcript_hash(alice.public_key, bob.public_key)
alice_aes_key = derive_session_key(alice_ss, salt=salt)  # 32 byte
bob_aes_key = derive_session_key(bob_ss, salt=salt)
assert alice_aes_key == bob_aes_key
```

### Post-Quantum Mode

```python
from ml_kem import MLKEM
from kdf import transcript_hash, derive_session_key

kem = MLKEM("ML-KEM-768")
bob = kem.keygen()
alice = kem.encapsulate(bob.public_key)
bob_ss = kem.decapsulate(bob.private_key, alice.ciphertext)

salt = transcript_hash(bob.public_key, alice.ciphertext)
alice_aes_key = derive_session_key(alice.shared_secret, salt=salt)
bob_aes_key = derive_session_key(bob_ss, salt=salt)
assert alice_aes_key == bob_aes_key
```

Khóa 32 byte đầu ra được chuyển trực tiếp sang module AES-256-GCM của thành viên phụ trách mã hóa. Nonce GCM vẫn phải được sinh và quản lý ở module AES; không được suy ra bằng cách tái sử dụng khóa hoặc nonce cũ.

## 6. Quy ước giao thức đề xuất

- `info` mặc định của HKDF: `CryptoShield/FileTransfer/v1/AES-256-GCM`.
- Salt là `SHA-256` của transcript có đóng khung độ dài, giúp hai bên tạo cùng ngữ cảnh.
- Phần chữ ký/xác thực cần ký hoặc xác thực transcript gồm định danh phiên, thuật toán, public key/ciphertext và nonce/message ID.
- Không ghi private key, shared secret hay AES key vào log.
- Public key phải được xác thực; ECDH/ML-KEM riêng lẻ không tự ngăn MITM/key substitution.

## 7. Lưu ý bảo mật quan trọng

`ml_kem.py` là bản tham chiếu phục vụ môn học. Nó không constant-time, không xóa khóa khỏi bộ nhớ và không phải mô-đun FIPS-validated. Dùng thư viện/provider mật mã đã được kiểm thử và duy trì khi triển khai thực tế.

Đề cương không chỉ định đường cong ECDH. Quyết định của phần này là hỗ trợ cả P-256 và X25519, đồng thời chọn P-256 làm mặc định để thống nhất benchmark. Nhóm có thể đổi mặc định nhưng phải ghi rõ trong cấu hình và báo cáo.

## 8. Tài liệu chuẩn tham khảo

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*.
- NIST SP 800-56A Rev. 3, *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*.
- RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
- RFC 7748, *Elliptic Curves for Security*.
