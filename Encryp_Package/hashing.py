import hashlib

PACKAGE_DIGEST_DOMAIN = b"nhom7_DEMO\x00"
ALGOR={
    "SHA-256": hashlib.sha256,
    "SHA3-256": hashlib.sha3_256,
}

CHUNK_SIZE = 1024 * 1024
def hash_bytes(data: bytes, algor: str) -> bytes:
    if algor not in ALGOR.keys():
        raise ValueError("Sai thuat toan")
    hasher=ALGOR[algor]()
    hasher.update(data)
    return hasher.digest()

def hash_file(inp_path: str,algor: str) ->bytes:
    if algor not in ALGOR.keys():
        raise ValueError("Sai thuat toan")
    
    hasher=ALGOR[algor]()

    with open(inp_path,"rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.digest()

def attach_len(part: bytes) -> bytes: #gan do dai dang big endian vao truoc cac part de xac dinh tung phan gom nhung gi
    return len(part).to_bytes(8,"big")+part

def package_digest(AAD: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(PACKAGE_DIGEST_DOMAIN)

    for part in (AAD,nonce,ciphertext,tag):
        hasher.update(attach_len(bytes(part)))
    #thu tu quan trong vi no lien quan den code truoc

    return hasher.digest()


