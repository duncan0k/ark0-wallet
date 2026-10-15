//! Transactions: the segwit serialization (BIP-144), txid, sizes, the P2MR script-path signature
//! message (BIP-341 with ext_flag 1, as p2mr-ts computes it), and the witnesses of the three templates.
use crate::p2mr::{compact_size, is_p2mr, tagged_hash, Leaf, MLDSA44_SIGNATURE_CHUNKS};
use sha2::{Digest, Sha256};

/// Below 0xffffffff so that nLockTime applies; it also signals replaceability.
pub const SEQUENCE: u32 = 0xffff_fffd;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// In the byte order of the serialization, the reverse of how txids are shown.
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    /// From a txid as shown (hex, display order).
    pub fn from_display(txid_hex: &str, vout: u32) -> Option<Self> {
        let mut txid: [u8; 32] = hex::decode(txid_hex).ok()?.try_into().ok()?;
        txid.reverse();
        Some(OutPoint { txid, vout })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn display_txid(&self) -> String {
        display_hex(&self.txid)
    }
}

/// A hash in display order (reversed), as txids are shown.
pub fn display_hex(hash: &[u8; 32]) -> String {
    let mut r = *hash;
    r.reverse();
    hex::encode(r)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub sats: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sats.to_le_bytes());
        compact_size(self.script_pubkey.len(), out);
        out.extend_from_slice(&self.script_pubkey);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

fn hash256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

impl Transaction {
    /// The serialization, with the witnesses (marker and flag) when `witness` and any input has one.
    pub fn encode(&self, witness: bool) -> Vec<u8> {
        let witness = witness && self.inputs.iter().any(|i| !i.witness.is_empty());
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if witness {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        compact_size(self.inputs.len(), &mut out);
        for input in &self.inputs {
            out.extend_from_slice(&input.prevout.txid);
            out.extend_from_slice(&input.prevout.vout.to_le_bytes());
            out.push(0); // empty scriptSig
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        compact_size(self.outputs.len(), &mut out);
        for output in &self.outputs {
            output.encode(&mut out);
        }
        if witness {
            for input in &self.inputs {
                compact_size(input.witness.len(), &mut out);
                for element in &input.witness {
                    compact_size(element.len(), &mut out);
                    out.extend_from_slice(element);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// In serialization order; `display_hex` shows it.
    pub fn txid(&self) -> [u8; 32] {
        hash256(&self.encode(false))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn wtxid(&self) -> [u8; 32] {
        hash256(&self.encode(true))
    }

    pub fn sizes(&self) -> Sizes {
        let size = self.encode(true).len();
        let base = self.encode(false).len();
        let weight = base * 3 + size;
        Sizes { size, base, weight, vsize: weight.div_ceil(4) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Sizes {
    pub size: usize,
    pub base: usize,
    pub weight: usize,
    pub vsize: usize,
}

/// The 32-byte message a signature in a P2MR leaf signs: TapSighash over BIP-341's SigMsg with
/// SIGHASH_DEFAULT, ext_flag 1, no annex, no OP_CODESEPARATOR, and this leaf's hash and key_version.
/// `spent` are the outputs the inputs spend, one per input; the one at `index` must be a P2MR output.
pub fn script_path_sighash(tx: &Transaction, index: usize, spent: &[TxOut], leaf_hash: &[u8; 32], key_version: u8) -> [u8; 32] {
    assert_eq!(spent.len(), tx.inputs.len(), "one spent output per input");
    assert!(index < tx.inputs.len(), "an input of the transaction");
    assert!(is_p2mr(&spent[index].script_pubkey), "the input spends a P2MR output");
    let sha = |data: Vec<u8>| -> [u8; 32] { Sha256::digest(data).into() };
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.prevout.txid);
        prevouts.extend_from_slice(&input.prevout.vout.to_le_bytes());
        sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let mut amounts = Vec::new();
    let mut scripts = Vec::new();
    for output in spent {
        amounts.extend_from_slice(&output.sats.to_le_bytes());
        compact_size(output.script_pubkey.len(), &mut scripts);
        scripts.extend_from_slice(&output.script_pubkey);
    }
    let mut outputs = Vec::new();
    for output in &tx.outputs {
        output.encode(&mut outputs);
    }
    let mut msg = Vec::with_capacity(1 + 1 + 4 + 4 + 32 * 5 + 1 + 4 + 32 + 1 + 4);
    msg.push(0x00); // epoch
    msg.push(0x00); // SIGHASH_DEFAULT
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    msg.extend_from_slice(&sha(prevouts));
    msg.extend_from_slice(&sha(amounts));
    msg.extend_from_slice(&sha(scripts));
    msg.extend_from_slice(&sha(sequences));
    msg.extend_from_slice(&sha(outputs));
    msg.push(0x02); // spend_type: ext_flag 1, no annex
    msg.extend_from_slice(&(index as u32).to_le_bytes());
    msg.extend_from_slice(leaf_hash);
    msg.push(key_version);
    msg.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // no OP_CODESEPARATOR executed
    tagged_hash("TapSighash", &[&msg])
}

/// `<signature> <leaf> <control block>`.
pub fn schnorr_witness(signature: &[u8; 64], leaf: &Leaf) -> Vec<Vec<u8>> {
    vec![signature.to_vec(), leaf.script.clone(), leaf.control_block.clone()]
}

/// The signature in its five pieces, then the leaf and the control block.
pub fn mldsa44_witness(signature: &[u8], leaf: &Leaf) -> Vec<Vec<u8>> {
    assert_eq!(signature.len(), MLDSA44_SIGNATURE_CHUNKS.iter().sum::<usize>(), "an ML-DSA-44 signature");
    let mut witness = Vec::with_capacity(7);
    let mut at = 0;
    for n in MLDSA44_SIGNATURE_CHUNKS {
        witness.push(signature[at..at + n].to_vec());
        at += n;
    }
    witness.push(leaf.script.clone());
    witness.push(leaf.control_block.clone());
    witness
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::p2mr::tests::{h, vectors};

    #[test]
    fn display_order_round_trips() {
        let o = OutPoint::from_display("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 3).unwrap();
        assert_eq!(o.txid[0], 0xff);
        assert_eq!(o.display_txid(), "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    }

    #[test]
    fn unsigned_transactions_match_the_reference() {
        for s in vectors()["spends"].as_array().unwrap() {
            let tx = Transaction {
                version: 2,
                lock_time: s["lock_time"].as_u64().unwrap() as u32,
                inputs: s["inputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| TxIn {
                        prevout: OutPoint::from_display(i["txid"].as_str().unwrap(), i["vout"].as_u64().unwrap() as u32).unwrap(),
                        sequence: SEQUENCE,
                        witness: vec![],
                    })
                    .collect(),
                outputs: s["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| TxOut { sats: o["sats"].as_u64().unwrap(), script_pubkey: h(&o["script_pubkey"]) })
                    .collect(),
            };
            assert_eq!(hex::encode(tx.encode(true)), s["unsigned_hex"].as_str().unwrap(), "{}", s["description"]);
        }
    }
}
