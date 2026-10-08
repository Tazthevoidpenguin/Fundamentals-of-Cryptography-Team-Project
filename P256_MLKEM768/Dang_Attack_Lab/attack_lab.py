from pathlib import Path
import sys
import os

# cho phép file trong Dang_Attack_Lab import code ở thư mục cha
proj_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(proj_root))

# import các hàm tra đổi khóa
from ThangV2.hybrid_kex import (
    generate_receiver_keys, # receiver tạo khóa
    sender_establish, # sender tạo sesion_key
    receiver_establish, # receiver tạo sesion_key
)
from Encryp_Package.pipeline import seal_file, open_file # đóng gói file, mở file phía receiver 
from Encryp_Package.package import dec_package, enc_package # dong goi va giai ma package
from Encryp_Package.signature import gen_ecdsa_key # tạo cặp khóa kí ECDSA

test_file = proj_root / "test.txt" # đường dẫn tới file test

def setup_package(): # tạo package hợp lệ như luồng gửi file bình thường
    """
    Tạo một package hợp lệ giống luồng gửi file bình thường.
    Trả về các dữ liệu cần dùng cho các demo attack.
    """
    receiver_ecdh, receiver_mlkem = generate_receiver_keys() # tạo 2 cặp khóa

    sender_kex = sender_establish(
        receiver_ecdh.public_key,
        receiver_mlkem.public_key
    ) # tạo session_key để mã hóa

    sign_keys = gen_ecdsa_key() # tạo khóa kí

    package_bytes = seal_file(
        str(test_file),
        sender_kex,
        sign_keys.pri_key
    ) # tạo package gửi đi

    package = dec_package(package_bytes) # decode lấy header

    receiver_kex = receiver_establish(
        receiver_ecdh.private_key,
        receiver_mlkem.private_key,
        package.header
    ) # tạo lại session_key

    return {
        "receiver_ecdh": receiver_ecdh,
        "receiver_mlkem": receiver_mlkem,
        "sender_kex": sender_kex,
        "receiver_kex": receiver_kex,
        "sign_keys": sign_keys,
        "package_bytes": package_bytes,
    } # trả về 1 dict để demo attack dùng sau


def normal_flow(): # luồng bình thường
    print("\n=== DEMO 1: Luong chay binh thuong ===")

    data = setup_package() # tạo package

    plaintext = open_file(
        data["package_bytes"],
        data["receiver_kex"],
        data["sign_keys"].pub_key
    ) # mở package

    original = test_file.read_bytes() # đọc file

    if plaintext == original:
        print("[OK] Giai ma thanh cong, file khoi phuc trung voi file goc")
    else:
        print("[FAIL] Giai ma that bai, file khoi phuc khong trung voi file goc")


def demo_tamper_ciphertext(): # sửa ciphertext
    print("\n=== Tan cong sua ciphertext ===")

    data = setup_package()
    package = dec_package(data["package_bytes"])

    # sửa 1 byte trong ciphertext
    tampered = bytearray(package.ciphertext)
    tampered[0] ^= 1
    package.ciphertext = bytes(tampered)

    tampered_package_bytes = enc_package(package)

    try:
        open_file(
            tampered_package_bytes,
            data["receiver_kex"],
            data["sign_keys"].pub_key
        )
        print("[LO HONG] Package bi sua ciphertext nhung van duoc chap nhan")
    except Exception as e:
        print("[BI CHAN] Package bi sua ciphertext da bi tu choi")
        print("Ly do:", e)


def demo_tamper_header(): # sửa header / transcript
    print("\n=== Tan cong sua thong tin trao doi khoa ===")

    data = setup_package()
    package = dec_package(data["package_bytes"])

    # sửa transcript_hash trong header
    package.header.transcript_hash = b"\x00" * 32 # thay thành 32 byte 0x00

    tampered_package_bytes = enc_package(package) # đóng gói lại
    tampered_header = dec_package(tampered_package_bytes).header # lấy header

    try:
        receiver_establish(
            data["receiver_ecdh"].private_key,
            data["receiver_mlkem"].private_key,
            tampered_header
        )
        print("[LO HONG] Header bi sua nhung van duoc chap nhan")
    except Exception as e:
        print("[BI CHAN] He thong phat hien header da bi sua")
        print("Ly do:", e)


def demo_replay_attack(): # tấn công phát lại
    print("\n=== DEMO 4: Tan cong phat lai ===")

    data = setup_package()

    # lần 1: mở package hợp lệ
    open_file(
        data["package_bytes"],
        data["receiver_kex"],
        data["sign_keys"].pub_key
    )
    print("[OK] Lan 1: package hop le duoc mo thanh cong")

    # lần 2: gửi lại y nguyên package cũ
    try:
        package = dec_package(data["package_bytes"])

        open_file(
            data["package_bytes"],
            data["receiver_kex"],
            data["sign_keys"].pub_key
        )

        print("[LO HONG] Lan 2: he thong van chap nhan package cu bi gui lai")
        print("message_id bi lap lai:", package.header.message_id)

    except Exception as e:
        print("[BI CHAN] He thong da tu choi package cu bi gui lai")
        print("Ly do:", e)

def demo_key_substitution(): # man in the middle
    print("\n=== DEMO 5: Tan cong thay the khoa cong khai / MITM ===")

    # Bob thật
    bob_ecdh, bob_mlkem = generate_receiver_keys()

    # attacker tự tạo key của mình
    attacker_ecdh, attacker_mlkem = generate_receiver_keys()

    # sender bị lừa, tưởng public key của attacker là của Bob
    sender_kex = sender_establish(
        attacker_ecdh.public_key,
        attacker_mlkem.public_key
    )

    sign_keys = gen_ecdsa_key()

    package_bytes = seal_file(
        str(test_file),
        sender_kex,
        sign_keys.pri_key
    )

    package = dec_package(package_bytes) # attacker mở file

    # package được mã hóa cho key của attacker
    attacker_kex = receiver_establish(
        attacker_ecdh.private_key,
        attacker_mlkem.private_key,
        package.header
    )

    attacker_plaintext = open_file(
        package_bytes,
        attacker_kex,
        sign_keys.pub_key
    )

    if attacker_plaintext == test_file.read_bytes():
        print("[LO HONG] Attacker da giai ma duoc file sau khi thay the khoa cong khai")
    else:
        print("[BI CHAN] Attacker khong giai ma duoc file")

    # Bob không mở được vì private key của Bob không khớp header
    try:
        bob_kex = receiver_establish(
            bob_ecdh.private_key,
            bob_mlkem.private_key,
            package.header
        )

        open_file(
            package_bytes,
            bob_kex,
            sign_keys.pub_key
        )

        print("[KET QUA] Nguoi nhan van mo duoc package da bi thay khoa")
    except Exception as e:
        print("[KET QUA] Nguoi nhan khong mo duoc package nay")
        print("Ly do:", e)
        print("[KET LUAN] Package da bi ma hoa cho attacker, khong phai cho nguoi nhan")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def main():
    while True:
        print("\n========== MENU ATTACK  =============")
        print("1. Demo luong binh thuong")
        print("2. Demo tan cong sua ciphertext")
        print("3. Demo tan cong sua thong tin trao doi khoa")
        print("4. Demo tan cong phat lai")
        print("5. Demo tan cong thay the khoa cong khai / MITM")
        print("0. Thoat")

        choice = input("Chon demo muon chay: ")

        clear_screen()

        if choice == "1":
            normal_flow()
        elif choice == "2":
            demo_tamper_ciphertext()
        elif choice == "3":
            demo_tamper_header()
        elif choice == "4":
            demo_replay_attack()
        elif choice == "5":
            demo_key_substitution()
        elif choice == "0":
            print("Da thoat!")
            break
        else:
            print("Lua chon khong hop le, vui long chon lai")

        input("\nNhan Enter de quay lai menu...")

        clear_screen()


if __name__ == "__main__":
    main()