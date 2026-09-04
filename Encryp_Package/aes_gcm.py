import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE=32
NONCE=12
TAG=16

@dataclass (frozen=True) #da khoi tao thi ko the thay doi
class EncData:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

def valid_key(key:bytes)->bytes:
    if(len(key)!=KEY_SIZE):
        raise ValueError("Sai kich thuoc key")
    return key

def enc_bytes(key: bytes,plain: bytes, AAD: bytes)->EncData:
    key = valid_key(key)
    nonce= secrets.token_bytes(NONCE)
    combined = AESGCM(key).encrypt(nonce,plain,AAD)
    #tao ra 1 doi tuong AESGCM khoa key de ma hoa plaintext co xac thuc aad
    cipher=combined[:-TAG]
    tag=combined[-TAG:]

    return EncData(
        nonce=nonce,
        ciphertext=cipher,
        tag=tag
    )

def dec_bytes(key: bytes, payload: EncData, AAD: bytes) -> bytes:
    key=valid_key(key)
    if len(payload.nonce)!=NONCE:
        raise ValueError("Nonce khong hop le")
    if len(payload.tag)!=TAG:
        raise ValueError("Tag khong hop le")
    combined=payload.ciphertext+payload.tag
    
    return AESGCM(key).decrypt(payload.nonce,combined,AAD)

def enc_file(key: bytes,inp_path: str, AAD: bytes) -> EncData:
    with open(inp_path,"rb") as f:
        return enc_bytes(key,f.read(),AAD)

def dec_file(key: bytes,payload: EncData, AAD: bytes, out_path: str):
    data=dec_bytes(key,payload=payload,AAD=AAD)
    with open(out_path,"wb") as f:
        f.write(data)

