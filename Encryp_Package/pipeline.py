from package import (HybridKexResult,PackageHeader,SecurePackage,
                     get_AAD,enc_package,PACKAGE_VERSION,GROUP_ID,dec_package
                     )
from signature import sign_pack_digest,verify_ecdsa
from hashing import hash_bytes,package_digest
from aes_gcm import EncData, enc_bytes,dec_bytes
from pathlib import Path
import uuid

def seal_file(inp_path:str, kex_rs:HybridKexResult, pri_key) -> bytes:
    path=Path(inp_path)
    plaintext = path.read_bytes()
    plain_hash=hash_bytes(plaintext,"SHA-256")

    header = PackageHeader(
        version=PACKAGE_VERSION,
        group_id=GROUP_ID,
        algorithm_id=kex_rs.algorithm_id,
        session_id=kex_rs.session_id,
        message_id=str(uuid.uuid4()), 
        sender_ecdh_public=kex_rs.sender_ecdh_public,
        receiver_ecdh_public=kex_rs.receiver_ecdh_public,
        receiver_mlkem_public=kex_rs.receiver_mlkem_public,
        mlkem_ciphertext=kex_rs.mlkem_ciphertext,
        transcript_hash=kex_rs.transcript_hash,
        filename=path.name,
        plaintext_size=len(plaintext),
        plaintext_hash=plain_hash,
    )

    """
    uuid.uuid4() Trả về một chuỗi gồm 36 ký tự (bao gồm cả dấu gạch ngang) theo định dạng mẫu 12345678-1234-1234-1234-12345678abcde
    AI goi y =)))
    """

    AAD=get_AAD(header)
    encrypted = enc_bytes(kex_rs.session_key,plaintext,AAD)

    digest = package_digest(AAD,encrypted.nonce,encrypted.ciphertext,encrypted.tag)
    #tra ve chuoi 32 bytes de ki

    signature = sign_pack_digest(pri_key,digest)

    pack_enc = SecurePackage(header,encrypted.nonce,encrypted.ciphertext,encrypted.tag,signature)

    return enc_package(pack_enc) #tra bytes json utf-8 cua package


def open_file(pack_bytes:bytes,kex_rs: HybridKexResult, pub_key) -> bytes:
    package = dec_package(pack_bytes)
    header=package.header
    AAD=get_AAD(header)
    digest=package_digest(AAD,package.nonce,package.ciphertext,package.tag)
    if not verify_ecdsa(pub_key,digest,package.signature):
        raise ValueError("INVALID_SIGNATURE")
    if(
        header.algorithm_id!=kex_rs.algorithm_id or
        header.session_id!=kex_rs.session_id or
        header.transcript_hash!=kex_rs.transcript_hash or
        header.sender_ecdh_public!=kex_rs.sender_ecdh_public or
        header.receiver_ecdh_public!=kex_rs.receiver_ecdh_public or
        header.receiver_mlkem_public!=kex_rs.receiver_mlkem_public or
        header.mlkem_ciphertext!=kex_rs.mlkem_ciphertext
    ):
        raise ValueError("Sai package")
    #thuc ra cai tren chi can kiem tra script_hash la duoc roi nma cu day du cho chac =)))

    payload = EncData(package.nonce,package.ciphertext,package.tag)

    plaintext=dec_bytes(kex_rs.session_key,payload,AAD)

    if len(plaintext) != header.plaintext_size:
        raise ValueError("Size khong khop")

    if hash_bytes(plaintext,"SHA-256") != header.plaintext_hash:
        raise ValueError("Hash khong khop")

    return plaintext #tra bytes cua file da qua check

def main():
    from hybrid_kex_stub import establish_hybrid_demo
    from signature import gen_ecdsa_key


    """
    doan nay sau nay Truong lam UI thi sua thanh keo tha file nhe, hien tai dang hoi lo =)))
    voi luc day chac phai co file main.py rieng, de merge thi sua nha
    """
    inp_path=Path("test.txt")
    pack_path=Path("encrypted_file.json")
    restored_path=Path("check.txt")

    session = establish_hybrid_demo() #doan nay de Thang gui r t code lai
    sign_keys = gen_ecdsa_key()

    package_bytes = seal_file(inp_path,session.sender,sign_keys.pri_key)

    #ghi output
    pack_path.write_bytes(package_bytes)

    input("Patch file pls")
    patched_pack=pack_path.read_bytes()
    #restore pack
    restored_data=open_file(patched_pack,session.receiver,sign_keys.pub_key)
    restored_path.write_bytes(restored_data)


if __name__ == "__main__":
    main()

