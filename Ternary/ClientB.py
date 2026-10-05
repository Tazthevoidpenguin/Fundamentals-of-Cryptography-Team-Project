import json
import secrets
from pathlib import Path
from hashlib import sha3_512


bin_tern = {
    "00": "-",
    "01": "+",
    "10": "0",
}

tern_bin = {
    "-": "00",
    "+": "01",
    "0": "10",
}

tern_val = {
    "-": 0,
    "+": 1,
    "0": 2,
}

val_tern = {
    0: "-",
    1: "+",
    2: "0",
}

file = Path(__file__).with_name("shared_data.json")

with file.open(encoding="utf-8") as f:
    data = json.load(f)

PASSWORD = data["password"]
tern_table = tuple(data["tern_table"])
del data


def RNG(length: int) -> str:
    return "".join(secrets.choice("01") for _ in range(length))


def bin_to_tern(binary: str) -> str:
    trits = []
    for index in range(0, len(binary) - 1, 2):
        cell = binary[index : index + 2]
        trit = bin_tern.get(cell)
        if trit is not None:
            trits.append(trit)

    return "".join(trits)


def tern_to_bin(ternary: str) -> str:
    return "".join(tern_bin[trit] for trit in ternary)


def mod(S1: str,S2: str) -> str:
    return "".join(
        val_tern[
            (tern_val[a] + tern_val[b]) % 3
        ]
        for a,b in zip(S1,S2)
    )


def get_STT(MD):
    STT=""
    for idx in range(0,len(MD),2):
        x=MD[idx]
        y=MD[idx+1]
        row=tern_table[x]

        for k in range(16):
            STT+=row[(y+k)%256]

    return STT


def create_pri_key(STT,IM):
    private_key=""

    for i in range(len(IM)):
        if IM[i]=="1" and STT[i]!="0":
            if STT[i]=="-":
                private_key+="0"
            else:
                private_key+="1"

    return private_key


if __name__ == "__main__":
    TRN="0+-++--+0000-+-0-0-0+-0+"
    TIN="0101010101000000000001010100010000010000000101000001010000010000010001000001010000010101000000000101000000000101010100000100010100000000000100010101000101010100000000000101010000000101010101000001010101000101010101010101000000000000000101010000010100000101010000010100010000000000000000000001010000010001010101000001010101000101010001010000010001000101010000010100010101000000000101010000000001000001010101000101010001000000000100000001010100010101010101010100010001000001010100000101000001010101000100010100000000010000000001000100000001000101000001000000000101000101010001000000000101010000000001010101000100010101010100010001000001000000010001010101000101010100010001000001000101000100010101000001010000010101000100000101000100010001000000010000000001000001000000010000010000010000010001000100000000010001010100010101010000000101010101000101010101010100000101010001000100010000000101010000010101010100010100000000000001010100000000000001010001000101000001010000000001000100010100000100000001010000000001000100010001010101"

    password_bits="".join(f"{byte:08b}" for byte in PASSWORD.encode())
    TPW=bin_to_tern(password_bits)

    TDS=mod(TRN,TPW)
    BDS=tern_to_bin(TDS)

    MD=sha3_512(BDS.encode()).digest()
    STT=get_STT(MD)

    BPM=""

    for i in range(0,len(TIN),2):
        if TIN[i:i+2]=="00":
            BPM+="0"
        else:
            BPM+="1"

    MD_bin=""
    IM=""

    for byte in MD:
        MD_bin+=format(byte,"08b")

    for a,b in zip(BPM,MD_bin):
        IM+=str(int(a)^int(b))

    pri_key=create_pri_key(STT,IM)

    print("Private key:",pri_key)
