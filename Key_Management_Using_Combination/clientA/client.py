import base64
import hashlib
import json
import secrets
import socket
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "127.0.0.1"
PORT = 4444
CODE_DIR = Path(__file__).resolve().parent


def send(request, show_error=True):
    try:
        with socket.create_connection((HOST, PORT)) as connection:
            connection.sendall((json.dumps(request) + "\n").encode("utf-8"))
            response = json.loads(connection.makefile("r", encoding="utf-8").readline())
        if not response.get("ok"):
            if show_error:
                print("Loi:", response.get("error"))
            return None
        return response
    except Exception as error:
        if show_error:
            print("Khong ket noi duoc server:", error)
        return None


def aes_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode("ascii")).digest()


def generate_key(state):
    params = send({"action": "parameters"})
    if not params:
        return

    g = params["g"]
    n = int(params["n"], 16)
    private_key = secrets.randbelow(n - 3) + 2
    public_key = pow(g, private_key, n)
    rs = send(
        {"action": "register", "name": state["name"], "public_key": hex(public_key)}
    )
    if rs:
        state.update({"g": g, "n": n, "private_key": private_key})
        print("Da tao khoa va gui khoa cong khai len server")


def create_shared_key(state):
    if "private_key" not in state:
        print("Hay tao khoa truoc")
        return

    peer = input("Ten doi tac: ").strip()

    if get_shared_key(state["name"], peer, False) is not None:
        print(f"Da co khoa chung voi {peer}")
        return

    rs = send({"action": "get_public_key", "name": peer}, False)
    if not rs:
        print(f"Khong tim thay khoa cong khai cua {peer}")
        return

    peer_public = int(rs["public_key"], 16)
    shared_secret = pow(peer_public, state["private_key"], state["n"])
    key = base64.b64encode(aes_key(shared_secret)).decode("ascii")
    rs = send(
        {
            "action": "store_shared_key",
            "name": state["name"],
            "peer": peer,
            "shared_key": key,
        }
    )
    if rs:
        print(f"Da tao khoa chung voi {peer}")


def get_shared_key(name, peer, show_error=True):
    rs = send(
        {"action": "get_shared_key", "name": name, "peer": peer}, show_error
    )
    if rs:
        return base64.b64decode(rs["shared_key"])
    return None


def up_file(state):
    receiver = input("Ten nguoi nhan: ").strip()
    file_path = CODE_DIR / input("Ten file: ").strip().strip('"')
    key = get_shared_key(state["name"], receiver, False)
    if not key:
        print("Chua co khoa chung, hay tao khoa chung truoc")
        return

    nonce = secrets.token_bytes(12)
    aad = f"{state['name']}|{receiver}|{file_path.name}".encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, file_path.read_bytes(), aad)
    rs = send(
        {
            "action": "upload",
            "sender": state["name"],
            "receiver": receiver,
            "filename": file_path.name,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
    )
    if rs:
        print("Da ma hoa va gui file. Ma file:", rs["file_id"])


def down_file(state):
    rs = send({"action": "list_files", "name": state["name"]})
    if not rs or not rs["files"]:
        print("Khong co file tren server")
        return

    for item in rs["files"]:
        print(f"{item['file_id']} - {item['filename']} - tu {item['sender']}")

    file_id = input("Nhap ma file: ").strip()
    rs = send({"action": "download", "name": state["name"], "file_id": file_id})
    if not rs:
        return

    item = rs["file"]
    key = get_shared_key(state["name"], item["sender"], False)
    if not key:
        print("Khong tim thay khoa chung de giai ma")
        return

    aad = f"{item['sender']}|{state['name']}|{item['filename']}".encode("utf-8")
    try:
        content = AESGCM(key).decrypt(base64.b64decode(item["nonce"]), base64.b64decode(item["ciphertext"]), aad)
    except InvalidTag:
        print("Khong giai ma duoc file")
        return

    output_path = CODE_DIR / item["filename"]
    output_path.write_bytes(content)
    print("Da giai ma file:", output_path)


def destroy_key(state):
    if send({"action": "destroy", "name": state["name"]}):
        name = state["name"]
        state.clear()
        state["name"] = name
        print("Da huy khoa")


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else input("Ten client: ").strip()
    state = {"name": name}
    menu = (
        "\n1. Tao khoa\n"
        "2. Tao khoa chung\n"
        "3. Ma hoa va gui file\n"
        "4. Tai va giai ma file\n"
        "5. Doi khoa\n"
        "6. Huy khoa\n"
        "0. Thoat\n"
    )

    try:
        while True:
            choice = input(menu + "Lua chon: ").strip()
            if choice == "1":
                generate_key(state)
            elif choice == "2":
                create_shared_key(state)
            elif choice == "3":
                up_file(state)
            elif choice == "4":
                down_file(state)
            elif choice == "5":
                generate_key(state)
                print("Da xoa khoa va file cu, hay tao lai khoa chung")
            elif choice == "6":
                destroy_key(state)
            elif choice == "0":
                break
            else:
                print("Lua chon khong hop le")
    except KeyboardInterrupt:
        pass
    finally:
        send({"action": "destroy", "name": state["name"]}, False)


if __name__ == "__main__":
    main()
