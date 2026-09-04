from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


"""
tham khao tai day https://mojoauth.com/keypair-generation/generate-keypair-using-ecdsa-with-python#serializing-and-storing-keys
"""
SIG_DOMAIN = b"nhom7_DEMO_sign\x00"
ECDSA_ID = "ECDSA-P256-SHA256"

@dataclass (frozen=True)
class SignKey:
    algor:str
    pri_key: object
    pub_key: object

def gen_ecdsa_key() -> SignKey:
    pri_key=ec.generate_private_key(ec.SECP256R1()) #tra ve object EllipticCurvePrivateKey
    pub_key=pri_key.public_key()
    return SignKey(ECDSA_ID,pri_key,pub_key)


def sign_pack_digest(pri_key,dig:bytes)->bytes:
    if len(dig)!=32:
        raise ValueError("Sai do dai package digest")
    mess=SIG_DOMAIN+dig
    return pri_key.sign(mess,ec.ECDSA(hashes.SHA256()))

def verify_ecdsa(pub_key,dig:bytes,sign:bytes) -> bool:
    if len(dig)!=32:
        raise ValueError("Sai do dai package digest")
    mess=SIG_DOMAIN+dig

    try:
        pub_key.verify(sign,mess,ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    
def xuat_pub_key(pub_key) -> bytes:
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub_pem
