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

The pq2 template ("e2-pq2") has two keys per output, both at account 0 and attempt 0, at a fresh index on
the receiving chain (0) or the change chain (1): an ML-DSA-44 key (32 bytes of output, KeyGen_internal) and
an SLH-DSA-SHA2-128s key (48 bytes of output: SK.seed, SK.prf, PK.seed; FIPS 205 slh_keygen_internal).
Their public keys and the pq2 address are computed here too, by a plain implementation of the two key
generations (FIPS 204 Algorithm 6, FIPS 205 Algorithm 18) and of the P2MR tree, so that the vectors do not
come from the code they test.
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
# The pq2 rows: these indices on both chains.
PQ2_INDICES = [0, 1, 19]
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


def key(seed, network, algorithm, template, attempt, chain=0, index=0, length=32):
    label = info([b"ark0-wallet", b"v1", network, algorithm.encode(), template.encode(),
                  struct.pack(">I", 0), struct.pack(">I", chain), struct.pack(">I", index), bytes([attempt])])
    return label, hkdf_sha512(seed, SALT, label, length)


# ---- ML-DSA-44 key generation (FIPS 204 Algorithm 6, KeyGen_internal) ----

Q = 8380417
N = 256
ZETA = 1753


def _bitrev8(i):
    return int(f"{i:08b}"[::-1], 2)


ZETAS = [pow(ZETA, _bitrev8(i), Q) for i in range(N)]


def ntt(w):
    w = list(w)
    m, length = 0, 128
    while length >= 1:
        start = 0
        while start < N:
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            start += 2 * length
        length //= 2
    return w


def ntt_inverse(w):
    w = list(w)
    m, length = 256, 1
    while length < N:
        start = 0
        while start < N:
            m -= 1
            z = Q - ZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = z * (t - w[j + length]) % Q
            start += 2 * length
        length *= 2
    f = 8347681  # 256^-1 mod q
    return [x * f % Q for x in w]


def rej_ntt_poly(seed):
    stream = hashlib.shake_128(seed).digest(894 * 3)
    out, pos = [], 0
    while len(out) < N:
        if pos + 3 > len(stream):
            stream = hashlib.shake_128(seed).digest(len(stream) * 2)
        z = stream[pos] | stream[pos + 1] << 8 | (stream[pos + 2] & 0x7F) << 16
        pos += 3
        if z < Q:
            out.append(z)
    return out


def rej_bounded_poly(seed):
    stream = hashlib.shake_256(seed).digest(1024)
    out, pos = [], 0
    while len(out) < N:
        if pos >= len(stream):
            stream = hashlib.shake_256(seed).digest(len(stream) * 2)
        b = stream[pos]
        pos += 1
        for z in (b & 15, b >> 4):
            if z < 15 and len(out) < N:
                out.append((2 - z % 5) % Q)  # eta = 2
    return out


def mldsa44_public_key(xi):
    k, l = 4, 4
    h = hashlib.shake_256(xi + bytes([k, l])).digest(128)
    rho, rho2 = h[:32], h[32:96]
    a = [[rej_ntt_poly(rho + bytes([s, r])) for s in range(l)] for r in range(k)]
    s1 = [rej_bounded_poly(rho2 + struct.pack("<H", r)) for r in range(l)]
    s2 = [rej_bounded_poly(rho2 + struct.pack("<H", r + l)) for r in range(k)]
    s1_hat = [ntt(p) for p in s1]
    pk = bytearray(rho)
    for r in range(k):
        acc = [0] * N
        for s in range(l):
            acc = [(x + y * z) % Q for x, y, z in zip(acc, a[r][s], s1_hat[s])]
        t = [(x + y) % Q for x, y in zip(ntt_inverse(acc), s2[r])]
        t1 = [(x - ((x % 8192) - 8192 if x % 8192 > 4096 else x % 8192)) >> 13 for x in t]  # Power2Round, d = 13
        bits = sum(c << (10 * i) for i, c in enumerate(t1))
        pk += bits.to_bytes(320, "little")
    return bytes(pk)


# ---- SLH-DSA-SHA2-128s key generation (FIPS 205 Algorithm 18, slh_keygen_internal) ----

SLH_N, SLH_HP, SLH_D, SLH_LEN, SLH_W = 16, 9, 7, 35, 16
WOTS_HASH, WOTS_PK, TREE, WOTS_PRF = 0, 1, 2, 5


def _adrs_c(layer, tree, kind, keypair=0, chain_or_height=0, hash_or_index=0):
    """The 22-byte compressed address of the SHA-2 instances."""
    return bytes([layer]) + tree.to_bytes(8, "big") + bytes([kind]) + struct.pack(">III", keypair, chain_or_height, hash_or_index)


def _sha2_n(pk_seed, adrs, data):
    return hashlib.sha256(pk_seed + bytes(64 - SLH_N) + adrs + data).digest()[:SLH_N]


def slh_public_root(sk_seed, pk_seed):
    layer = SLH_D - 1

    def wots_pk(i):
        tops = b""
        for c in range(SLH_LEN):
            x = _sha2_n(pk_seed, _adrs_c(layer, 0, WOTS_PRF, i, c, 0), sk_seed)
            for j in range(SLH_W - 1):
                x = _sha2_n(pk_seed, _adrs_c(layer, 0, WOTS_HASH, i, c, j), x)
            tops += x
        return _sha2_n(pk_seed, _adrs_c(layer, 0, WOTS_PK, i), tops)

    nodes = [wots_pk(i) for i in range(1 << SLH_HP)]
    for z in range(1, SLH_HP + 1):
        nodes = [_sha2_n(pk_seed, _adrs_c(layer, 0, TREE, 0, z, i), nodes[2 * i] + nodes[2 * i + 1]) for i in range(len(nodes) // 2)]
    return nodes[0]


def slhdsa128s_public_key(seed48):
    sk_seed, pk_seed = seed48[:16], seed48[32:48]
    return pk_seed + slh_public_root(sk_seed, pk_seed)


# ---- the pq2 output: two leaves of version 0xe2 at depth one ----

def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def compact_size(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def tap_leaf(script, version=0xE2):
    return tagged("TapLeaf", bytes([version]) + compact_size(len(script)) + script)


def pq2_root(mldsa44_pk, slh_pk):
    s1 = (b"\x4d\x08\x02" + mldsa44_pk[:520] + b"\x4d\x08\x02" + mldsa44_pk[520:1040] + b"\x4d\x10\x01"
          + mldsa44_pk[1040:] + b"\xf0")
    slh1 = b"\x20" + slh_pk + b"\xf1"
    a, b = sorted([tap_leaf(s1), tap_leaf(slh1)])
    return tagged("TapBranch", a + b)


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def p2mr_address(root, hrp="tb"):
    """bech32m (BIP-350) of witness version 2."""
    acc, bits, data = 0, 0, [2]
    for byte in root:
        acc = acc << 8 | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append(acc >> bits & 31)
    if bits:
        data.append(acc << (5 - bits) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(expanded + data + [0] * 6) ^ 0x2BC830A3
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def pq2_row(seed, network, chain, index):
    ml_info, ml_seed = key(seed, network, "mldsa44", "e2-pq2", 0, chain, index, 32)
    slh_info, slh_seed = key(seed, network, "slhdsa128s", "e2-pq2", 0, chain, index, 48)
    assert (len(ml_info), len(slh_info)) == (89, 92)
    ml_pk = mldsa44_public_key(ml_seed)
    slh_pk = slhdsa128s_public_key(slh_seed)
    return {
        "template": "e2-pq2", "account": 0, "chain": chain, "index": index, "attempt": 0,
        "mldsa44": {"info": ml_info.hex(), "keygen_seed": ml_seed.hex(),
                    "public_key_sha256": hashlib.sha256(ml_pk).hexdigest()},
        "slhdsa128s": {"info": slh_info.hex(), "keygen_seed": slh_seed.hex(), "public_key": slh_pk.hex(),
                       "public_key_sha256": hashlib.sha256(slh_pk).hexdigest()},
        "address": p2mr_address(pq2_root(ml_pk, slh_pk)),
    }


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
        pq2 = [pq2_row(seed, network, chain, index) for chain in (0, 1) for index in PQ2_INDICES]
        wallets.append({"entropy": byte * 32, "phrase": phrase, "bip39_seed": seed.hex(), "keys": keys, "pq2": pq2})
    print(json.dumps({
        "generator": "tools/derivation/derive.py",
        "salt": SALT.decode(),
        "signet_challenge": CHALLENGE,
        "network_id": network.hex(),
        "wallets": wallets,
    }, indent=1))


if __name__ == "__main__":
    main()
