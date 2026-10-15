//! P2MR (BIP-360) as the Ark-0 test signet runs it, the parts this wallet needs: tagged hashes, the
//! three output templates, their leaves and control blocks, addresses, and the destinations it pays.
//!
//! A port of p2mr-ts, the library the Ark-0 web wallet vendors. `tests/vectors/p2mr.json` was made by that
//! code (tools/vectors), and the tests here and in `tx.rs` check every byte against it.
//!
//! The three templates are trees of two leaves at depth one:
//! - Schnorr: `<x-only key> OP_CHECKSIG` beside `OP_RETURN`, both leaf version 0xc0;
//! - ML-DSA-44 (M1): the S1 template of OP_CHECKMLDSA44 beside `OP_RETURN`, both 0xc0;
//! - mixed (M3, "S3"): the Schnorr leaf beside the S1 leaf, both 0xe0. Once the network's drill tripwire is
//!   pulled, elliptic-curve checks in 0xe0 leaves fail, and only the ML-DSA-44 leaf can spend.
use bech32::{Fe32, Hrp};
use sha2::{Digest, Sha256};

pub const LEAF_VERSION: u8 = 0xc0;
pub const TRIPWIRED_LEAF_VERSION: u8 = 0xe0;
/// The sibling of a template leaf: `OP_RETURN`, which can only fail.
pub const FAIL_LEAF: [u8; 1] = [0x6a];
pub const OP_CHECKMLDSA44: u8 = 0xf0;
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
/// The signature message's key_version: 0 for BIP-340 signatures, 1 for OP_CHECKMLDSA44.
pub const SCHNORR_KEY_VERSION: u8 = 0x00;
pub const MLDSA44_KEY_VERSION: u8 = 0x01;
/// The context string of every ML-DSA-44 signature OP_CHECKMLDSA44 checks.
pub const MLDSA44_CONTEXT: &[u8] = b"P2MR/MLDSA44/EXP0";
/// An ML-DSA-44 signature goes on the witness stack in these pieces (no element may exceed 520 bytes).
pub const MLDSA44_SIGNATURE_CHUNKS: [usize; 5] = [520, 520, 520, 520, 340];
/// The address prefix of every test network, Ark-0 included.
pub const HRP: &str = "tb";
#[cfg(test)]
const P2MR_WITNESS_VERSION: u8 = 2;

pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// Bitcoin's CompactSize length prefix.
pub fn compact_size(n: usize, out: &mut Vec<u8>) {
    let n = n as u64;
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// TapLeaf(leaf version || compact_size(len) || script), as BIP-341 defines it.
pub fn leaf_hash(script: &[u8], leaf_version: u8) -> [u8; 32] {
    debug_assert_eq!(leaf_version & 1, 0, "a leaf version is even");
    let mut data = Vec::with_capacity(script.len() + 4);
    data.push(leaf_version);
    compact_size(script.len(), &mut data);
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &[&data])
}

/// TapBranch of the two child hashes in lexicographic order.
pub fn branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        tagged_hash("TapBranch", &[a, b])
    } else {
        tagged_hash("TapBranch", &[b, a])
    }
}

/// `<x-only key> OP_CHECKSIG`.
pub fn schnorr_leaf_script(xonly: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(xonly);
    s.push(0xac);
    s
}

/// S1: the public key pushed in pieces of 520, 520 and 272 bytes (OP_PUSHDATA2), then OP_CHECKMLDSA44.
pub fn mldsa44_leaf_script(public_key: &[u8; MLDSA44_PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut s = Vec::with_capacity(3 + 520 + 3 + 520 + 3 + 272 + 1);
    s.extend_from_slice(&[0x4d, 0x08, 0x02]);
    s.extend_from_slice(&public_key[..520]);
    s.extend_from_slice(&[0x4d, 0x08, 0x02]);
    s.extend_from_slice(&public_key[520..1040]);
    s.extend_from_slice(&[0x4d, 0x10, 0x01]);
    s.extend_from_slice(&public_key[1040..]);
    s.push(OP_CHECKMLDSA44);
    s
}

/// A leaf a spend runs, with the control block that proves it is in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub script: Vec<u8>,
    pub version: u8,
    pub hash: [u8; 32],
    /// leaf version | 1, then the sibling's hash: every tree here is two leaves at depth one.
    pub control_block: Vec<u8>,
}

/// The root of two leaves at depth one, and each leaf with its control block.
fn pair(a: Vec<u8>, b: Vec<u8>, version: u8) -> ([u8; 32], Leaf, Leaf) {
    let (ha, hb) = (leaf_hash(&a, version), leaf_hash(&b, version));
    let control = |sibling: &[u8; 32]| {
        let mut c = Vec::with_capacity(33);
        c.push(version | 1);
        c.extend_from_slice(sibling);
        c
    };
    let root = branch_hash(&ha, &hb);
    let la = Leaf { control_block: control(&hb), script: a, version, hash: ha };
    let lb = Leaf { control_block: control(&ha), script: b, version, hash: hb };
    (root, la, lb)
}

/// `OP_2 <32-byte merkle root>`.
pub fn script_pubkey(root: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x52);
    s.push(0x20);
    s.extend_from_slice(root);
    s
}

pub fn is_p2mr(script_pubkey: &[u8]) -> bool {
    script_pubkey.len() == 34 && script_pubkey[0] == 0x52 && script_pubkey[1] == 0x20
}

/// The bech32m address of a merkle root: `tb1z…`.
pub fn address(root: &[u8; 32]) -> String {
    let hrp = Hrp::parse(HRP).expect("a valid prefix");
    bech32::segwit::encode(hrp, Fe32::Z, root).expect("a 32-byte witness v2 program encodes")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Schnorr,
    Mldsa44,
    Mixed,
}

/// Which leaf, and so which signature, a spend uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Path {
    Schnorr,
    Mldsa44,
}

/// One of the three outputs a key pair makes.
#[derive(Clone, Debug)]
pub struct Template {
    pub kind: Kind,
    #[cfg_attr(not(test), allow(dead_code))]
    pub root: [u8; 32],
    pub script_pubkey: Vec<u8>,
    pub address: String,
    /// The Schnorr leaf: the spending leaf of the Schnorr template, and the 0xe0 Schnorr leaf of the mixed one.
    pub schnorr_leaf: Option<Leaf>,
    /// The S1 leaf: the spending leaf of the ML-DSA-44 template, and the 0xe0 S1 leaf of the mixed one.
    pub mldsa44_leaf: Option<Leaf>,
}

impl Template {
    fn new(kind: Kind, root: [u8; 32], schnorr_leaf: Option<Leaf>, mldsa44_leaf: Option<Leaf>) -> Self {
        Template { kind, script_pubkey: script_pubkey(&root), address: address(&root), root, schnorr_leaf, mldsa44_leaf }
    }

    pub fn schnorr(xonly: &[u8; 32]) -> Self {
        let (root, leaf, _) = pair(schnorr_leaf_script(xonly), FAIL_LEAF.to_vec(), LEAF_VERSION);
        Template::new(Kind::Schnorr, root, Some(leaf), None)
    }

    pub fn mldsa44(public_key: &[u8; MLDSA44_PUBLIC_KEY_LEN]) -> Self {
        let (root, leaf, _) = pair(mldsa44_leaf_script(public_key), FAIL_LEAF.to_vec(), LEAF_VERSION);
        Template::new(Kind::Mldsa44, root, None, Some(leaf))
    }

    pub fn mixed(xonly: &[u8; 32], public_key: &[u8; MLDSA44_PUBLIC_KEY_LEN]) -> Self {
        let (root, schnorr, mldsa44) =
            pair(schnorr_leaf_script(xonly), mldsa44_leaf_script(public_key), TRIPWIRED_LEAF_VERSION);
        Template::new(Kind::Mixed, root, Some(schnorr), Some(mldsa44))
    }

    /// The leaf a spend along `path` runs, if this template has one.
    pub fn leaf(&self, path: Path) -> Option<&Leaf> {
        match path {
            Path::Schnorr => self.schnorr_leaf.as_ref(),
            Path::Mldsa44 => self.mldsa44_leaf.as_ref(),
        }
    }
}

/// A valid address of a kind that has spending rules on Ark-0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// Lower case.
    pub address: String,
    pub script_pubkey: Vec<u8>,
    /// The smallest output the node relays to this kind of script.
    pub dust: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationError {
    /// Not a segwit address: a typo, a bad checksum, the wrong checksum for its version, mixed case.
    NotAnAddress,
    /// A valid address of another network.
    OtherNetwork,
    /// A valid address of a version or length without spending rules here: anyone could spend it.
    Unsupported,
}

/// The web wallet's rule (dest.ts): version 0 with 20 or 32 bytes, version 1 with 32 (Taproot), version 2
/// with 32 (P2MR). Surrounding white space is ignored; one case throughout, as BIP-173 asks.
pub fn parse_destination(text: &str) -> Result<Destination, DestinationError> {
    let text = text.trim();
    let has_upper = text.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = text.chars().any(|c| c.is_ascii_lowercase());
    if text.is_empty() || (has_upper && has_lower) {
        return Err(DestinationError::NotAnAddress);
    }
    let lower = text.to_ascii_lowercase();
    let (hrp, version, program) = bech32::segwit::decode(&lower).map_err(|_| DestinationError::NotAnAddress)?;
    if hrp.as_str() != HRP {
        return Err(DestinationError::OtherNetwork);
    }
    let v = version.to_u8();
    let supported = matches!((v, program.len()), (0, 20) | (0, 32) | (1, 32) | (2, 32));
    if !supported {
        return Err(DestinationError::Unsupported);
    }
    let mut script_pubkey = Vec::with_capacity(program.len() + 2);
    script_pubkey.push(if v == 0 { 0 } else { 0x50 + v });
    script_pubkey.push(program.len() as u8);
    script_pubkey.extend_from_slice(&program);
    let dust = if v == 0 && program.len() == 20 { 294 } else { 330 };
    Ok(Destination { address: lower, script_pubkey, dust })
}

/// The merkle root of a P2MR address of this network, or None.
#[cfg(test)]
pub fn decode_p2mr_address(address: &str) -> Option<[u8; 32]> {
    let d = parse_destination(address).ok()?;
    if d.script_pubkey.len() == 34 && d.script_pubkey[0] == 0x50 + P2MR_WITNESS_VERSION {
        d.script_pubkey[2..].try_into().ok()
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    pub(crate) fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/p2mr.json")).expect("vectors parse")
    }

    pub(crate) fn h(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("a hex string")).expect("valid hex")
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn check_leaf(leaf: &Leaf, v: &Value) {
        assert_eq!(leaf.script.len() as u64, v["leaf_script_len"].as_u64().unwrap());
        assert_eq!(sha(&leaf.script), v["leaf_script_sha256"].as_str().unwrap());
        assert_eq!(hex::encode(leaf.hash), v["leaf_hash"].as_str().unwrap());
        assert_eq!(hex::encode(&leaf.control_block), v["control_block"].as_str().unwrap());
    }

    #[test]
    fn templates_match_the_reference() {
        for k in vectors()["keys"].as_array().unwrap() {
            let xonly: [u8; 32] = h(&k["xonly"]).try_into().unwrap();
            let seed: [u8; 32] = h(&k["seed"]).try_into().unwrap();
            let secret = crate::keys::Secret::Legacy { seed: crate::keys::SecretBytes(zeroize::Zeroizing::new(seed)) };
            let keys = crate::keys::Keys::from_secret(&secret).unwrap();
            assert_eq!(keys.xonly(Kind::Schnorr), xonly);
            assert_eq!(sha(keys.mldsa44_public_key(Kind::Mldsa44)), k["mldsa44_public_key_sha256"].as_str().unwrap());

            let s = Template::schnorr(&xonly);
            assert_eq!(s.address, k["schnorr"]["address"].as_str().unwrap());
            assert_eq!(hex::encode(&s.script_pubkey), k["schnorr"]["script_pubkey"].as_str().unwrap());
            assert_eq!(hex::encode(&s.schnorr_leaf.as_ref().unwrap().script), k["schnorr"]["leaf_script"].as_str().unwrap());
            check_leaf(s.schnorr_leaf.as_ref().unwrap(), &k["schnorr"]);

            let m = Template::mldsa44(keys.mldsa44_public_key(Kind::Mldsa44));
            assert_eq!(keys.template(Kind::Mldsa44).address, m.address);
            assert_eq!(m.address, k["mldsa44"]["address"].as_str().unwrap());
            assert_eq!(hex::encode(&m.script_pubkey), k["mldsa44"]["script_pubkey"].as_str().unwrap());
            check_leaf(m.mldsa44_leaf.as_ref().unwrap(), &k["mldsa44"]);

            let x = Template::mixed(&xonly, keys.mldsa44_public_key(Kind::Mldsa44));
            assert_eq!(keys.template(Kind::Mixed).address, x.address);
            assert_eq!(x.address, k["mixed"]["address"].as_str().unwrap());
            assert_eq!(hex::encode(&x.script_pubkey), k["mixed"]["script_pubkey"].as_str().unwrap());
            check_leaf(x.schnorr_leaf.as_ref().unwrap(), &k["mixed"]["schnorr_leaf"]);
            check_leaf(x.mldsa44_leaf.as_ref().unwrap(), &k["mixed"]["mldsa44_leaf"]);
            assert_eq!(decode_p2mr_address(&x.address), Some(x.root));
        }
    }

    #[test]
    fn destinations_match_the_reference() {
        for d in vectors()["destinations"].as_array().unwrap() {
            let text = d["text"].as_str().unwrap();
            let got = parse_destination(text);
            match d["result"].as_str().unwrap() {
                "ok" => {
                    let got = got.unwrap_or_else(|e| panic!("{text:?}: {e:?}"));
                    assert_eq!(got.address, d["address"].as_str().unwrap());
                    assert_eq!(hex::encode(&got.script_pubkey), d["script_pubkey"].as_str().unwrap());
                    assert_eq!(got.dust, d["dust"].as_u64().unwrap());
                }
                "not_an_address" => assert_eq!(got, Err(DestinationError::NotAnAddress), "{text:?}"),
                "other_network" => assert_eq!(got, Err(DestinationError::OtherNetwork), "{text:?}"),
                "unsupported" => assert_eq!(got, Err(DestinationError::Unsupported), "{text:?}"),
                other => panic!("unknown result {other}"),
            }
        }
    }

    #[test]
    fn refuses_mixed_case_and_unsupported_programs() {
        assert_eq!(parse_destination("tb1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX"), Err(DestinationError::NotAnAddress));
        // BIP-350's version 16 test address, re-encoded for tb: a valid address nobody can be paid at here.
        let v16 = bech32::segwit::encode(Hrp::parse("tb").unwrap(), Fe32::try_from(16u8).unwrap(), &[0x75, 0x1e]).unwrap();
        assert_eq!(parse_destination(&v16), Err(DestinationError::Unsupported));
        let v2_short = bech32::segwit::encode(Hrp::parse("tb").unwrap(), Fe32::Z, &[7u8; 20]).unwrap();
        assert_eq!(parse_destination(&v2_short), Err(DestinationError::Unsupported));
    }
}
