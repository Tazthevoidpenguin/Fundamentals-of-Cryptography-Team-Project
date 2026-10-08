import json
import socketserver
import uuid
from pathlib import Path


HOST = "127.0.0.1"
PORT = 4444
DATA_FILE = Path(__file__).with_name("server_data.json")

# Tham so Diffie-Hellman mac dinh
G = 2
N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)


def new_data():
    return {
        "parameters": {"g": G, "n": hex(N)},
        "public_keys": {},
        "shared_keys": {},
        "stored_files": {},
    }


def load_data():
    try:
        if DATA_FILE.exists():
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return new_data()


def save_data():
    DATA_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def pair_key(first, second):
    return "|".join(sorted((first, second)))


data = load_data()


def process(request):
    action = request.get("action")

    if action == "parameters":
        return {"ok": True, **data["parameters"]}

    if action == "register":
        name = request["name"]
        public_key = int(request["public_key"], 16)
        if not 2 <= public_key <= N - 2:
            return {"ok": False, "error": "Khoa cong khai khong hop le"}

        # Doi khoa moi thi xoa cac khoa chung cu
        for pair in list(data["shared_keys"]):
            if name in pair.split("|"):
                del data["shared_keys"][pair]
        for file_id, item in list(data["stored_files"].items()):
            if name in (item["sender"], item["receiver"]):
                del data["stored_files"][file_id]
        data["public_keys"][name] = request["public_key"]
        save_data()
        return {"ok": True}

    if action == "get_public_key":
        name = request["name"]
        key = data["public_keys"].get(name)
        if not key:
            return {"ok": False, "error": f"{name} chua tao khoa"}
        return {"ok": True, "public_key": key}

    if action == "store_shared_key":
        name = request["name"]
        peer = request["peer"]
        if name not in data["public_keys"] or peer not in data["public_keys"]:
            return {"ok": False, "error": "Hai ben phai tao khoa truoc"}

        pair = pair_key(name, peer)
        old_key = data["shared_keys"].get(pair)
        if old_key and old_key != request["shared_key"]:
            return {"ok": False, "error": "Hai ben tinh ra khoa khac nhau"}
        data["shared_keys"][pair] = request["shared_key"]
        save_data()
        return {"ok": True}

    if action == "get_shared_key":
        key = data["shared_keys"].get(pair_key(request["name"], request["peer"]))
        if not key:
            return {"ok": False, "error": "Chua tao khoa chung"}
        return {"ok": True, "shared_key": key}

    if action == "upload":
        file_id = uuid.uuid4().hex[:12]
        data["stored_files"][file_id] = {
            "sender": request["sender"],
            "receiver": request["receiver"],
            "filename": request["filename"],
            "nonce": request["nonce"],
            "ciphertext": request["ciphertext"],
        }
        save_data()
        return {"ok": True, "file_id": file_id}

    if action == "list_files":
        files = []
        for file_id, item in data["stored_files"].items():
            if item["receiver"] == request["name"]:
                files.append(
                    {"file_id": file_id, "sender": item["sender"], "filename": item["filename"]}
                )
        return {"ok": True, "files": files}

    if action == "download":
        item = data["stored_files"].get(request["file_id"])
        if not item or item["receiver"] != request["name"]:
            return {"ok": False, "error": "Khong tim thay file"}
        return {"ok": True, "file": item}

    if action == "destroy":
        name = request["name"]
        data["public_keys"].pop(name, None)
        for pair in list(data["shared_keys"]):
            if name in pair.split("|"):
                del data["shared_keys"][pair]
        for file_id, item in list(data["stored_files"].items()):
            if name in (item["sender"], item["receiver"]):
                del data["stored_files"][file_id]
        save_data()
        return {"ok": True}

    return {"ok": False, "error": "Yeu cau khong hop le"}


class ServerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            request = json.loads(self.rfile.readline().decode("utf-8"))
            response = process(request)
        except Exception as error:
            response = {"ok": False, "error": str(error)}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


if __name__ == "__main__":
    save_data()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), ServerHandler) as server:
        print(f"Server dang chay tai {HOST}:{PORT}")
        server.serve_forever()
