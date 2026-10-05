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


def tern_to_bin(ternary: str):
    return "".join(tern_bin[trit] for trit in ternary)


def mod(S1: str, S2: str):
    return "".join(
        val_tern[
            (tern_val[a] + tern_val[b]) % 3
        ]
        for a,b in zip(S1, S2)
    )


def get_STT(MD):
    STT=""
    for idx in range(0,len(MD),2):
        x=MD[idx]
        y=MD[idx+1]
        row=tern_table[x]

        for k in range(16):
            STT+=row[(y+k)%256] #x,y la byte, trits la bit nen phai loop

    return STT


def create_IM(STT):
    """
    - tao random mask 512 bit
    - STT[i]=0 -> mask[i]=0
    - chon ngau nhien cac vi tri STT='-' de bo sung thanh 1
    """
    while True:
        IM=list(RNG(len(STT)))

        for i in range(len(STT)):
            if STT[i]=="0":
                IM[i]="0"

        zeros=[i for i in range(len(STT)) if STT[i]=="-" and IM[i]=="0"]

        while IM.count("1")<256 and zeros:
            idx=secrets.choice(zeros)
            zeros.remove(idx)
            IM[idx]="1"

        if IM.count("1")==256:
            return "".join(IM)


def create_pri_key(STT,IM):
    private_key=""

    for i in range(len(STT)):
        if IM[i]=="1" and STT[i]!="0":
            if STT[i]=="-":
                private_key+="0"
            else:
                private_key+="1"

    return private_key


if __name__ == "__main__":
    bits=RNG(len(PASSWORD))
    TRN=bin_to_tern(bits)
    password_bits="".join(f"{byte:08b}" for byte in PASSWORD.encode())
    TPW=bin_to_tern(password_bits)

    TDS=mod(TRN, TPW)
    BDS=tern_to_bin(TDS)

    MD=sha3_512(BDS.encode()).digest()
    STT=get_STT(MD)

    IM=create_IM(STT)
    pri_key=create_pri_key(STT,IM)

    MD_bin=""
    BPM=""

    for byte in MD:
        MD_bin+=format(byte,"08b")

    for a,b in zip(IM,MD_bin):
        BPM+=str(int(a)^int(b))

    TIN=""

    for bit in BPM:
        if bit=="0":
            TIN+="00"
        else:
            TIN+="01"

    print("Private key:",pri_key)
    print("TIN:",TIN)
    print("TRN:",TRN)


