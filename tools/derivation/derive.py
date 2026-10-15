"""The wallet's key derivation (src-tauri/src/keys.rs), computed independently with Python's standard
library only: PBKDF2 for the BIP-39 seed, HMAC for HKDF-SHA-512 (RFC 5869). It prints the test vectors
that src-tauri/tests/vectors/derivation.json holds and keys.rs is tested against.

    python tools/derivation/derive.py > src-tauri/tests/vectors/derivation.json

A 24-word wallet's 64-byte BIP-39 seed (no passphrase) is HKDF's input key material, the salt is fixed, and
the info names the wallet, the derivation's version, the network (SHA-256 of the signet challenge), the
algorithm, the template, the account, the chain, the index and an attempt counter, each field with a
two-byte big-endian length in front. Every template has keys of its own. A BIP-340 key takes the first
attempt from 0 whose output is a valid secret key; an ML-DSA-44 key is FIPS 204 KeyGen on the output of
attempt 0.
"""
import hashlib
import hmac
import json
import struct

CHALLENGE = "5121026fc5d8e79a9fbc8bc3dea07d82641d16717ce0b000c13c512d8e8c1788c6e5da51ae"
SALT = b"ark0-wallet key derivation v1"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Each template and the algorithms of its leaves.
TEMPLATES = [("c0-schnorr", ["schnorr"]), ("c0-mldsa44", ["mldsa44"]), ("e0-hybrid", ["schnorr", "mldsa44"])]
# 24-word phrases of the BIP-39 reference vectors (entropy repeated over 32 bytes).
WALLETS = [
    ("00", " ".join(["abandon"] * 23 + ["art"])),
    ("7f", " ".join(["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful"] * 2
                    + ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "title"])),
    ("80", " ".join(["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid"] * 2
                    + ["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "bless"])),
    ("ff", " ".join(["zoo"] * 23 + ["vote"])),
]


def info(fields):
    return b"".join(struct.pack(">H", len(f)) + f for f in fields)


def hkdf_sha512(ikm, salt, info_bytes, length):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info_bytes + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def key(seed, network, algorithm, template, attempt):
    label = info([b"ark0-wallet", b"v1", network, algorithm.encode(), template.encode(),
                  struct.pack(">I", 0), struct.pack(">I", 0), struct.pack(">I", 0), bytes([attempt])])
    return label, hkdf_sha512(seed, SALT, label, 32)


def main():
    network = hashlib.sha256(bytes.fromhex(CHALLENGE)).digest()
    wallets = []
    for byte, phrase in WALLETS:
        seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048, 64)
        keys = []
        for template, algorithms in TEMPLATES:
            for algorithm in algorithms:
                attempt = 0
                label, out = key(seed, network, algorithm, template, attempt)
                while algorithm == "schnorr" and not 0 < int.from_bytes(out, "big") < CURVE_ORDER:
                    attempt += 1
                    label, out = key(seed, network, algorithm, template, attempt)
                keys.append({"template": template, "algorithm": algorithm, "account": 0, "chain": 0, "index": 0,
                             "attempt": attempt, "info": label.hex(),
                             ("secret_key" if algorithm == "schnorr" else "keygen_seed"): out.hex()})
        wallets.append({"entropy": byte * 32, "phrase": phrase, "bip39_seed": seed.hex(), "keys": keys})
    print(json.dumps({
        "generator": "tools/derivation/derive.py",
        "salt": SALT.decode(),
        "signet_challenge": CHALLENGE,
        "network_id": network.hex(),
        "wallets": wallets,
    }, indent=1))


if __name__ == "__main__":
    main()
