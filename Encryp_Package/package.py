import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#doan nay dang de test, sau nay merge file sua sau
PACKAGE_VERSION=1
GROUP_ID="nhom_7"
HYBRID_ALGORITHM="P256_MLKEM768_HYBRID"
NONCE=12
TAG=16
TRANSCRIPT_HASH_SIZE=32
MAX_PACKAGE_SIZE=200 * 1024 * 1024  #200 chunk 1024*1024

@dataclass
class HybridKexResult:
    algorithm_id: str
    session_id: bytes #16 bytes

    #32 bytes
    session_key: bytes

    # Du lieu cong khai trong package
    transcript_hash: bytes #32 bytes
    sender_ecdh_public: bytes
    receiver_ecdh_public: bytes
    receiver_mlkem_public: bytes
    mlkem_ciphertext: bytes


@dataclass
class PackageHeader:
    version: int
    group_id: str
    algorithm_id: str

    session_id: bytes
    message_id: str

    sender_ecdh_public: bytes
    receiver_ecdh_public: bytes
    receiver_mlkem_public: bytes
    mlkem_ciphertext: bytes
    transcript_hash: bytes

    filename: str
    plaintext_size: int
    plaintext_hash: bytes


@dataclass
class SecurePackage:
    header: PackageHeader
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    signature: bytes


class InvalidPackageError(ValueError):
    pass


def enc_bytes(val: bytes) -> str:
    return base64.b64encode(val).decode("utf-8")

def dec_bytes(val: str)-> bytes:
    if not isinstance(val, str):
        raise InvalidPackageError("Du lieu Base64 phai la chuoi")
    try:
        return base64.b64decode(val, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvalidPackageError("Du lieu Base64 khong hop le") from exc


def header_to_obj(header: PackageHeader) -> dict[str,Any]:
    rs={}
    rs["version"]=header.version
    rs["group_id"]=header.group_id
    rs["algo_id"]=header.algorithm_id
    rs["ses_id"]=enc_bytes(header.session_id)
    rs["mes_id"]=header.message_id
    rs["sender_ecdh_pub"]=enc_bytes(header.sender_ecdh_public)
    rs["receiver_ecdh_pub"]=enc_bytes(header.receiver_ecdh_public)
    rs["receiver_mlkem_pub"]=enc_bytes(header.receiver_mlkem_public)
    rs["mlkem_ciphertext"]=enc_bytes(header.mlkem_ciphertext)
    rs["trans_hash"]=enc_bytes(header.transcript_hash)
    rs["plaintext_hash"]=enc_bytes(header.plaintext_hash)

    rs["filename"]=header.filename
    rs["plaintext_size"]=header.plaintext_size

    return rs

def get_AAD(header: PackageHeader) ->bytes:
    obj=header_to_obj(header)
    return json.dumps(obj,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode("utf-8")

def obj_to_header(obj: dict[str,Any]) -> PackageHeader:
    header_fields={
        "version", "group_id", "algo_id", "ses_id", "mes_id",
        "sender_ecdh_pub", "receiver_ecdh_pub", "receiver_mlkem_pub",
        "mlkem_ciphertext", "trans_hash", "plaintext_hash",
        "filename", "plaintext_size",
    }
    if not isinstance(obj, dict) or set(obj)!=header_fields:
        raise InvalidPackageError("Cac field cua header khong hop le")

    return PackageHeader(
        version=obj["version"],
        group_id=obj["group_id"],
        algorithm_id=obj["algo_id"],
        session_id=dec_bytes(obj["ses_id"]),
        message_id=obj["mes_id"],
        sender_ecdh_public=dec_bytes(obj["sender_ecdh_pub"]),
        receiver_ecdh_public=dec_bytes(obj["receiver_ecdh_pub"]),
        receiver_mlkem_public=dec_bytes(obj["receiver_mlkem_pub"]),
        mlkem_ciphertext=dec_bytes(obj["mlkem_ciphertext"]),
        transcript_hash=dec_bytes(obj["trans_hash"]),
        filename=obj["filename"],
        plaintext_size=obj["plaintext_size"],
        plaintext_hash=dec_bytes(obj["plaintext_hash"]),
    )


def valid_header(header: PackageHeader):
    if not isinstance(header, PackageHeader):
        return False
    if not all(isinstance(val, bytes) for val in (
        header.session_id,
        header.sender_ecdh_public,
        header.receiver_ecdh_public,
        header.receiver_mlkem_public,
        header.mlkem_ciphertext,
        header.transcript_hash,
        header.plaintext_hash,
    )):
        return False
    if not isinstance(header.message_id, str) or not header.message_id:
        return False
    if not isinstance(header.filename, str) or not header.filename:
        return False
    if Path(header.filename).name != header.filename:
        return False
    
    #doan tren check kieu du lieu do truoc do test co gap loi @@

    if(not isinstance(header.version, int)
       or isinstance(header.version, bool)
       or header.version!=PACKAGE_VERSION
       or header.group_id!=GROUP_ID
       or header.algorithm_id!=HYBRID_ALGORITHM
       or len(header.session_id)!=16
       or len(header.transcript_hash)!=TRANSCRIPT_HASH_SIZE
       or len(header.plaintext_hash)!=32
       or not isinstance(header.plaintext_size, int)
       or isinstance(header.plaintext_size, bool)
       or header.plaintext_size<0
       ):
        return False
    return True


def valid_package(pack: SecurePackage):
    #check kieu du lieu tuong tu ben tren
    if not isinstance(pack, SecurePackage) or not valid_header(pack.header):
        return False
    if not all(isinstance(val, bytes) for val in (
        pack.nonce, pack.ciphertext, pack.tag, pack.signature
    )):
        return False
    
   
    if (
        len(pack.nonce)!=NONCE
        or len(pack.tag)!=TAG
        or not pack.signature
        or (len(pack.ciphertext)+NONCE+TAG+len(pack.signature))>MAX_PACKAGE_SIZE
    ):
        return False
    return True


def enc_package(pack:SecurePackage) -> bytes:
    if not valid_package(pack):
        raise InvalidPackageError("Package khong hop le")

    obj={}
    obj["header"]=header_to_obj(pack.header)
    obj["nonce"]=enc_bytes(pack.nonce)
    obj["ciphertext"]=enc_bytes(pack.ciphertext)
    obj["signature"]=enc_bytes(pack.signature)
    obj["tag"]=enc_bytes(pack.tag)

    data=json.dumps(obj,sort_keys=True,separators=(",",":")).encode("UTF-8")
    if len(data)>MAX_PACKAGE_SIZE:
        raise InvalidPackageError("Do dai package vuot qua nguong hop le")
    return data


def dec_package(data: bytes) -> SecurePackage:
    if not isinstance(data, bytes):
        raise InvalidPackageError("Package phai la bytes")
    if len(data)>MAX_PACKAGE_SIZE:
        raise InvalidPackageError("Data vuot qua nguong cho phep")

    try:
        pack=json.loads(data.decode("UTF-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidPackageError("JSON package khong hop le") from exc
    package_fields={"header", "nonce", "ciphertext", "signature", "tag"}
    if not isinstance(pack, dict) or set(pack)!=package_fields:
        raise InvalidPackageError("Cac field cua package khong hop le")

    Pack_Header=obj_to_header(pack["header"])
    nonce=dec_bytes(pack["nonce"])
    ciphertext=dec_bytes(pack["ciphertext"])
    sign=dec_bytes(pack["signature"])
    tag=dec_bytes(pack["tag"])

    SecPack=SecurePackage(
        header=Pack_Header,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        signature=sign,
    )
    if not valid_package(SecPack):
        raise InvalidPackageError("Package khong hop le")
    return SecPack
