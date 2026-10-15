//! Proofs against Ark-0's block signatures: an API's confirmation count alone never settles a payment.
use crate::chain::{PQBLOCK_HEIGHT, PQBLOCK_KEY};
use crate::keys::ARK0_CHALLENGE;
use crate::mldsa;
use crate::p2mr::{compact_size, tagged_hash};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ops::Range;

pub const REQUIRED_BLOCKS: u32 = 6;
const MAX_BRANCH: usize = 32;
// A block has at most a million bytes of non-witness data: bound the hex length before decoding.
const MAX_COINBASE_BYTES: usize = 1_000_000;
const CONTEXT: &[u8] = b"SIGNET/PQBLOCK/EXP0";
const COMMITMENT: &[u8] = &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
const PQ_HEADER: &[u8] = b"PQB1\x01";
const SIGNET_HEADER: &[u8] = &[0xec, 0xc7, 0xda, 0xa2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    Malformed,
    Bounds,
    BeforeActivation,
    Heights,
    Work,
    Coinbase,
    CoinbaseBranch,
    Linkage,
    Commitment,
    Signature,
    TransactionBranch,
}

fn hash256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

fn number(value: Option<&Value>) -> Result<u32, ProofError> {
    value.and_then(Value::as_u64).and_then(|n| n.try_into().ok()).ok_or(ProofError::Malformed)
}

fn bytes(value: Option<&Value>, max: usize) -> Result<Vec<u8>, ProofError> {
    let text = value.and_then(Value::as_str).ok_or(ProofError::Malformed)?;
    if text.len() > max * 2 {
        return Err(ProofError::Bounds);
    }
    hex::decode(text).map_err(|_| ProofError::Malformed)
}

fn hash(value: Option<&Value>) -> Result<[u8; 32], ProofError> {
    bytes(value, 32)?.try_into().map_err(|_| ProofError::Malformed)
}

fn branch(value: Option<&Value>) -> Result<Vec<[u8; 32]>, ProofError> {
    let list = value.and_then(Value::as_array).ok_or(ProofError::Malformed)?;
    if list.len() > MAX_BRANCH {
        return Err(ProofError::Bounds);
    }
    list.iter().map(|v| hash(Some(v))).collect()
}

fn merkle(mut leaf: [u8; 32], siblings: &[[u8; 32]], mut index: u32) -> Option<[u8; 32]> {
    for sibling in siblings {
        // An odd level duplicates its last left node only: the duplicate on the right has no index of its own.
        if index & 1 != 0 && &leaf == sibling {
            return None;
        }
        let mut pair = [0u8; 64];
        let (left, right) = if index & 1 == 0 { (&leaf, sibling) } else { (sibling, &leaf) };
        pair[..32].copy_from_slice(left);
        pair[32..].copy_from_slice(right);
        leaf = hash256(&pair);
        index >>= 1;
    }
    (index == 0).then_some(leaf)
}

// Like Bitcoin's SetCompact: refuse negative, zero, and targets beyond uint256.
fn target(bits: u32) -> Option<[u8; 32]> {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    if word == 0 || bits & 0x0080_0000 != 0
        || size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)
    {
        return None;
    }
    let mut out = [0u8; 32];
    let offset = size.saturating_sub(3) as usize;
    for (i, byte) in word.to_le_bytes()[..3].iter().enumerate() {
        if offset + i < out.len() {
            out[offset + i] = *byte;
        }
    }
    Some(out)
}

fn work(header: &[u8; 80]) -> bool {
    let bits = u32::from_le_bytes(header[72..76].try_into().expect("four bytes"));
    target(bits).is_some_and(|t| hash256(header).iter().rev().cmp(t.iter().rev()) != std::cmp::Ordering::Greater)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ProofError> {
        let end = self.at.checked_add(len).ok_or(ProofError::Bounds)?;
        let part = self.bytes.get(self.at..end).ok_or(ProofError::Coinbase)?;
        self.at = end;
        Ok(part)
    }

    fn size(&mut self, max: usize) -> Result<usize, ProofError> {
        let first = self.take(1)?[0];
        let (n, minimum) = match first {
            0xfd => (u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")) as u64, 0xfd),
            0xfe => (u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")) as u64, 0x1_0000),
            0xff => (u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")), 0x1_0000_0000),
            n => (u64::from(n), 0),
        };
        if n < minimum {
            return Err(ProofError::Coinbase);
        }
        if n > max as u64 {
            return Err(ProofError::Bounds);
        }
        Ok(n as usize)
    }
}

fn height_prefix(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![0];
    }
    if height <= 16 {
        return vec![0x50 + height as u8];
    }
    let mut n = height;
    let mut data = Vec::new();
    while n != 0 {
        data.push(n as u8);
        n >>= 8;
    }
    if data.last().is_some_and(|b| b & 0x80 != 0) {
        data.push(0);
    }
    let mut script = vec![data.len() as u8];
    script.extend(data);
    script
}

struct Coinbase<'a> {
    bytes: &'a [u8],
    // The script carries its CompactSize length: replacing the script must rewrite it.
    output: Range<usize>,
    script: &'a [u8],
}

impl<'a> Coinbase<'a> {
    fn parse(bytes: &'a [u8], height: u32) -> Result<Self, ProofError> {
        if bytes.len() > MAX_COINBASE_BYTES {
            return Err(ProofError::Bounds);
        }
        let mut r = Reader { bytes, at: 0 };
        r.take(4)?;
        if r.size(1)? != 1 || r.take(32)? != [0u8; 32] || r.take(4)? != [0xff; 4] {
            return Err(ProofError::Coinbase);
        }
        let len = r.size(100)?;
        if len < 2 {
            return Err(ProofError::Coinbase);
        }
        if !r.take(len)?.starts_with(&height_prefix(height)) {
            return Err(ProofError::Heights);
        }
        r.take(4)?;
        // Even an output with an empty script takes nine bytes: a count cannot drive an unbounded loop or allocation.
        let count = r.size(MAX_COINBASE_BYTES / 9)?;
        if count == 0 || count > (bytes.len() - r.at) / 9 {
            return Err(ProofError::Coinbase);
        }
        let mut commitment = None;
        for _ in 0..count {
            r.take(8)?;
            let start = r.at;
            let len = r.size(MAX_COINBASE_BYTES)?;
            let script = r.take(len)?;
            if script.starts_with(COMMITMENT) {
                commitment = Some((start..r.at, script));
            }
        }
        r.take(4)?;
        if r.at != bytes.len() {
            return Err(ProofError::Coinbase);
        }
        let (output, script) = commitment.ok_or(ProofError::Commitment)?;
        Ok(Coinbase { bytes, output, script })
    }

    fn stripped(&self) -> Vec<u8> {
        let mut out = self.bytes[..self.output.start].to_vec();
        compact_size(44, &mut out);
        out.extend_from_slice(&self.script[..38]);
        out.push(5);
        out.extend_from_slice(PQ_HEADER);
        out.extend_from_slice(&self.bytes[self.output.end..]);
        out
    }
}

fn signet_push(bytes: &[u8]) -> bool {
    let mut r = Reader { bytes, at: 0 };
    let parsed = (|| {
        let opcode = r.take(1)?[0];
        let (len, minimum) = match opcode {
            1..=75 => (u32::from(opcode), 1),
            0x4c => (u32::from(r.take(1)?[0]), 76),
            0x4d => (u32::from(u16::from_le_bytes(r.take(2)?.try_into().expect("two bytes"))), 256),
            0x4e => (u32::from_le_bytes(r.take(4)?.try_into().expect("four bytes")), 65_536),
            _ => return Err(ProofError::Commitment),
        };
        if len < minimum || len <= 4 || len as u64 > MAX_COINBASE_BYTES as u64 {
            return Err(ProofError::Commitment);
        }
        let solution = r.take(len as usize)?;
        Ok(solution.starts_with(SIGNET_HEADER) && r.at == bytes.len())
    })();
    parsed.unwrap_or(false)
}

fn signature(script: &[u8]) -> Result<&[u8; mldsa::SIGNATURE_LEN], ProofError> {
    let end = 46 + mldsa::SIGNATURE_LEN;
    if script.len() < end || !script.starts_with(COMMITMENT)
        || script[38..41] != [0x4d, 0x79, 0x09] || &script[41..46] != PQ_HEADER
        || (script.len() > end && !signet_push(&script[end..]))
    {
        return Err(ProofError::Commitment);
    }
    script[46..end].try_into().map_err(|_| ProofError::Commitment)
}

fn message(header: &[u8; 80], root: &[u8; 32]) -> [u8; 32] {
    let challenge = Sha256::digest(hex::decode(ARK0_CHALLENGE).expect("pinned challenge"));
    tagged_hash("SignetPQBlock", &[&challenge, &header[..36], root, &header[68..72]])
}

/// Only this uses the deployed key; a test key cannot come in from an API or a caller.
pub fn verify(txid: &str, answer: &Value) -> Result<u32, ProofError> {
    let key: [u8; mldsa::PUBLIC_KEY_LEN] = hex::decode(PQBLOCK_KEY).expect("pinned key").try_into().expect("ML-DSA-44 public key");
    verify_with_key(txid, answer, &key)
}

fn verify_with_key(txid: &str, answer: &Value, key: &[u8; mldsa::PUBLIC_KEY_LEN]) -> Result<u32, ProofError> {
    if !crate::api::is_txid(txid) || answer.get("txid").and_then(Value::as_str) != Some(txid) {
        return Err(ProofError::Malformed);
    }
    let mut tx = hash(answer.get("txid"))?;
    tx.reverse();
    let height = number(answer.get("height"))?;
    let tip = number(answer.get("tip"))?;
    if height < PQBLOCK_HEIGHT {
        return Err(ProofError::BeforeActivation);
    }
    if tip < height {
        return Err(ProofError::Heights);
    }
    let blocks = answer.get("blocks").and_then(Value::as_array).ok_or(ProofError::Malformed)?;
    if blocks.len() > REQUIRED_BLOCKS as usize {
        return Err(ProofError::Bounds);
    }
    let count = (u64::from(tip) - u64::from(height) + 1).min(u64::from(REQUIRED_BLOCKS)) as usize;
    if blocks.len() != count {
        return Err(ProofError::Heights);
    }
    let mut previous = None;
    for (i, block) in blocks.iter().enumerate() {
        if i != 0 && (block.get("tx_index").is_some() || block.get("tx_branch").is_some()) {
            return Err(ProofError::Malformed);
        }
        let expected = height.checked_add(i as u32).ok_or(ProofError::Heights)?;
        if number(block.get("height"))? != expected {
            return Err(ProofError::Heights);
        }
        let header: [u8; 80] = bytes(block.get("header"), 80)?.try_into().map_err(|_| ProofError::Malformed)?;
        if !work(&header) {
            return Err(ProofError::Work);
        }
        if previous.is_some_and(|hash: [u8; 32]| header[4..36] != hash) {
            return Err(ProofError::Linkage);
        }
        let raw = bytes(block.get("coinbase"), MAX_COINBASE_BYTES)?;
        let siblings = branch(block.get("coinbase_branch"))?;
        let root: [u8; 32] = header[36..68].try_into().expect("merkle root");
        if merkle(hash256(&raw), &siblings, 0) != Some(root) {
            return Err(ProofError::CoinbaseBranch);
        }
        let cb = Coinbase::parse(&raw, expected)?;
        let sig = signature(cb.script)?;
        let stripped_root = merkle(hash256(&cb.stripped()), &siblings, 0).ok_or(ProofError::CoinbaseBranch)?;
        if !mldsa::verify(sig, &message(&header, &stripped_root), CONTEXT, key) {
            return Err(ProofError::Signature);
        }
        if i == 0 {
            let index = number(block.get("tx_index"))?;
            let tx_siblings = branch(block.get("tx_branch"))?;
            if tx_siblings.len() != siblings.len() || merkle(tx, &tx_siblings, index) != Some(root) {
                return Err(ProofError::TransactionBranch);
            }
        }
        previous = Some(hash256(&header));
    }
    Ok(count as u32)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tx::display_hex;
    use serde_json::json;
    use std::sync::OnceLock;

    fn key() -> &'static mldsa::KeyPair {
        static KEY: OnceLock<mldsa::KeyPair> = OnceLock::new();
        KEY.get_or_init(|| mldsa::keypair_from_seed(&[42; 32]).unwrap())
    }

    fn check(answer: &Value) -> Result<u32, ProofError> {
        verify_synthetic(answer["txid"].as_str().unwrap(), answer)
    }

    pub(crate) fn verify_synthetic(txid: &str, answer: &Value) -> Result<u32, ProofError> {
        verify_with_key(txid, answer, &key().public)
    }

    fn tree(mut leaves: Vec<[u8; 32]>, mut index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut branch = Vec::new();
        while leaves.len() > 1 {
            if leaves.len() % 2 != 0 {
                leaves.push(*leaves.last().unwrap());
            }
            branch.push(leaves[index ^ 1]);
            leaves = leaves.chunks_exact(2).map(|pair| {
                let mut bytes = pair[0].to_vec();
                bytes.extend_from_slice(&pair[1]);
                hash256(&bytes)
            }).collect();
            index >>= 1;
        }
        (leaves[0], branch)
    }

    fn push(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match data.len() {
            0..=75 => out.push(data.len() as u8),
            76..=255 => out.extend_from_slice(&[0x4c, data.len() as u8]),
            256..=65_535 => {
                out.push(0x4d);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            }
            _ => {
                out.push(0x4e);
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            }
        }
        out.extend_from_slice(data);
        out
    }

    fn commitment() -> Vec<u8> {
        let mut script = COMMITMENT.to_vec();
        script.extend_from_slice(&[0; 32]);
        let mut data = PQ_HEADER.to_vec();
        data.extend_from_slice(&[0; mldsa::SIGNATURE_LEN]);
        script.extend(push(&data));
        script
    }

    fn coinbase(script_sig: &[u8], scripts: &[Vec<u8>]) -> Vec<u8> {
        let mut tx = 2u32.to_le_bytes().to_vec();
        tx.push(1);
        tx.extend_from_slice(&[0; 32]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        compact_size(script_sig.len(), &mut tx);
        tx.extend_from_slice(script_sig);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        compact_size(scripts.len(), &mut tx);
        for script in scripts {
            tx.extend_from_slice(&0u64.to_le_bytes());
            compact_size(script.len(), &mut tx);
            tx.extend_from_slice(script);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx
    }

    fn mine(header: &mut [u8; 80]) {
        for nonce in 0..=u32::MAX {
            header[76..].copy_from_slice(&nonce.to_le_bytes());
            if work(header) {
                return;
            }
        }
        panic!("test target must be easy");
    }

    fn synthetic_block(height: u32, prev: [u8; 32], script_sig: &[u8], others: &[[u8; 32]]) -> Value {
        let script = commitment();
        let mut raw = coinbase(script_sig, &[script.clone()]);
        let mut header = [0u8; 80];
        header[..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        header[4..36].copy_from_slice(&prev);
        header[68..72].copy_from_slice(&1_791_693_688u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        let mut leaves = vec![hash256(&raw)];
        leaves.extend_from_slice(others);
        let (_, cb_branch) = tree(leaves.clone(), 0);
        let offset = raw.len() - 4 - script.len() + 46;
        let mut stripped_script = script[..38].to_vec();
        stripped_script.push(5);
        stripped_script.extend_from_slice(PQ_HEADER);
        let stripped = coinbase(script_sig, &[stripped_script]);
        let root = merkle(hash256(&stripped), &cb_branch, 0).unwrap();
        let sig = mldsa::sign_deterministic(&message(&header, &root), CONTEXT, &key().secret).unwrap();
        raw[offset..offset + sig.len()].copy_from_slice(&sig);
        leaves[0] = hash256(&raw);
        let (root, cb_branch) = tree(leaves.clone(), 0);
        let index = leaves.len() - 1;
        let (_, tx_branch) = tree(leaves, index);
        header[36..68].copy_from_slice(&root);
        mine(&mut header);
        json!({
            "height": height, "header": hex::encode(header), "coinbase": hex::encode(raw),
            "coinbase_branch": cb_branch.iter().map(hex::encode).collect::<Vec<_>>(),
            "tx_index": index, "tx_branch": tx_branch.iter().map(hex::encode).collect::<Vec<_>>()
        })
    }

    pub(crate) fn synthetic_count(count: u32) -> u32 {
        check(&chain(count)).unwrap()
    }

    pub(crate) fn chain(count: u32) -> Value {
        let others = [hash256(b"transaction one"), hash256(b"transaction two")];
        let mut blocks = Vec::new();
        let mut prev = [0; 32];
        for i in 0..count {
            let h = PQBLOCK_HEIGHT + i;
            let mut block = synthetic_block(h, prev, &height_prefix(h), &others);
            prev = hash256(&hex::decode(block["header"].as_str().unwrap()).unwrap());
            if i != 0 {
                block.as_object_mut().unwrap().remove("tx_index");
                block.as_object_mut().unwrap().remove("tx_branch");
            }
            blocks.push(block);
        }
        json!({"txid": display_hex(&others[1]), "height": PQBLOCK_HEIGHT, "tip": PQBLOCK_HEIGHT + count - 1, "blocks": blocks})
    }

    // A whole block's witnesses are no part of a txid: keep the other serialized bytes and build both real branches.
    fn legacy_transaction(r: &mut Reader<'_>) -> Vec<u8> {
        let start = r.at;
        r.take(4).unwrap();
        let segwit = r.bytes.get(r.at..r.at + 2) == Some(&[0, 1][..]);
        if segwit {
            r.take(2).unwrap();
        }
        let body_start = r.at;
        let inputs = r.size(MAX_COINBASE_BYTES).unwrap();
        for _ in 0..inputs {
            r.take(36).unwrap();
            let len = r.size(MAX_COINBASE_BYTES).unwrap();
            r.take(len).unwrap();
            r.take(4).unwrap();
        }
        let outputs = r.size(MAX_COINBASE_BYTES).unwrap();
        for _ in 0..outputs {
            r.take(8).unwrap();
            let len = r.size(MAX_COINBASE_BYTES).unwrap();
            r.take(len).unwrap();
        }
        let body_end = r.at;
        if segwit {
            for _ in 0..inputs {
                let items = r.size(MAX_COINBASE_BYTES).unwrap();
                for _ in 0..items {
                    let len = r.size(MAX_COINBASE_BYTES).unwrap();
                    r.take(len).unwrap();
                }
            }
        }
        let mut tx = r.bytes[start..start + 4].to_vec();
        tx.extend_from_slice(&r.bytes[body_start..body_end]);
        tx.extend_from_slice(r.take(4).unwrap());
        tx
    }

    fn whole_block(text: &str, height: u32, index: usize) -> Value {
        let bytes = hex::decode(text.trim()).unwrap();
        let mut r = Reader { bytes: &bytes, at: 0 };
        let header = r.take(80).unwrap();
        let count = r.size(MAX_COINBASE_BYTES).unwrap();
        let txs: Vec<Vec<u8>> = (0..count).map(|_| legacy_transaction(&mut r)).collect();
        assert_eq!(r.at, bytes.len());
        let leaves: Vec<_> = txs.iter().map(|tx| hash256(tx)).collect();
        let (_, cb_branch) = tree(leaves.clone(), 0);
        let (_, tx_branch) = tree(leaves.clone(), index);
        json!({
            "txid": display_hex(&leaves[index]), "height": height, "tip": height,
            "blocks": [{"height": height, "header": hex::encode(header), "coinbase": hex::encode(&txs[0]),
                "coinbase_branch": cb_branch.iter().map(hex::encode).collect::<Vec<_>>(),
                "tx_index": index, "tx_branch": tx_branch.iter().map(hex::encode).collect::<Vec<_>>() }]
        })
    }

    pub(crate) fn real_proof() -> Value {
        whole_block(include_str!("../tests/vectors/pqblock/m2_block_20000.hex"), 20_000, 0)
    }

    #[test]
    fn real_block_and_deployment_key() {
        let key = hex::decode(PQBLOCK_KEY).unwrap();
        assert_eq!(key.len(), mldsa::PUBLIC_KEY_LEN);
        assert_eq!(hex::encode(Sha256::digest(&key)), "eee8548f51f25492de3ae430b7ce7ec549edfaa663b8f577f026ce0498fdd6ad");
        assert_eq!(hex::encode(key), include_str!("../tests/vectors/pqblock/block-key.hex").trim());
        let answer = whole_block(include_str!("../tests/vectors/pqblock/m2_block_20000.hex"), 20_000, 0);
        assert_eq!(verify(answer["txid"].as_str().unwrap(), &answer), Ok(1));
        let header = hex::decode(answer["blocks"][0]["header"].as_str().unwrap()).unwrap();
        assert_eq!(display_hex(&hash256(&header)), "000001153177f182a96b4ad6903ed9279cef82b0cfd340f85b55d1ac81ccc1d4");
    }

    #[test]
    fn real_rejected_blocks_fail_for_the_documented_reason() {
        for (text, error) in [
            (include_str!("../tests/vectors/pqblock/m2_badblock_nopush.hex"), ProofError::Commitment),
            (include_str!("../tests/vectors/pqblock/m2_badblock_nonpush.hex"), ProofError::Commitment),
            (include_str!("../tests/vectors/pqblock/m2_badblock_trailing.hex"), ProofError::Commitment),
            (include_str!("../tests/vectors/pqblock/m2_badblock_flipped.hex"), ProofError::Signature),
            (include_str!("../tests/vectors/pqblock/m2_badblock_otherkey.hex"), ProofError::Signature),
        ] {
            let answer = whole_block(text, 20_095, 0);
            assert_eq!(verify(answer["txid"].as_str().unwrap(), &answer), Err(error));
        }
        let answer = whole_block(include_str!("../tests/vectors/pqblock/m2_badblock_trailing.hex"), 20_095, 0);
        let block = &answer["blocks"][0];
        let raw = hex::decode(block["coinbase"].as_str().unwrap()).unwrap();
        let cb = Coinbase::parse(&raw, 20_095).unwrap();
        let header: [u8; 80] = hex::decode(block["header"].as_str().unwrap()).unwrap().try_into().unwrap();
        let siblings = branch(block.get("coinbase_branch")).unwrap();
        let root = merkle(hash256(&cb.stripped()), &siblings, 0).unwrap();
        let sig = cb.script[46..46 + mldsa::SIGNATURE_LEN].try_into().unwrap();
        let key = hex::decode(PQBLOCK_KEY).unwrap().try_into().unwrap();
        assert!(mldsa::verify(sig, &message(&header, &root), CONTEXT, &key));
        assert_eq!(signature(cb.script), Err(ProofError::Commitment));
        for (text, other_key) in [
            (include_str!("../tests/vectors/pqblock/m2_badblock_flipped.hex"), false),
            (include_str!("../tests/vectors/pqblock/m2_badblock_otherkey.hex"), true),
        ] {
            let answer = whole_block(text, 20_095, 0);
            let block = &answer["blocks"][0];
            let raw = hex::decode(block["coinbase"].as_str().unwrap()).unwrap();
            let cb = Coinbase::parse(&raw, 20_095).unwrap();
            let header = hex::decode(block["header"].as_str().unwrap()).unwrap().try_into().unwrap();
            let siblings = branch(block.get("coinbase_branch")).unwrap();
            let root = merkle(hash256(&cb.stripped()), &siblings, 0).unwrap();
            let mut sig = *signature(cb.script).unwrap();
            let mut public = key;
            if other_key {
                let seed = Sha256::digest(b"ark0 m2 negative blocks at 20000: another ML-DSA-44 key, public, test only").into();
                public = *mldsa::keypair_from_seed(&seed).unwrap().public;
            } else {
                sig[95] ^= 1;
            }
            assert!(mldsa::verify(&sig, &message(&header, &root), CONTEXT, &public));
            assert!(!mldsa::verify(&sig, &message(&header, &root), b"P2MR/MLDSA44/EXP0", &public));
        }
    }

    #[test]
    fn synthetic_chains_prove_one_through_six_blocks_and_odd_merkle_levels() {
        for n in 1..=REQUIRED_BLOCKS {
            assert_eq!(synthetic_count(n), n);
        }
        let mut answer = chain(6);
        answer["tip"] = json!(u32::MAX);
        assert_eq!(check(&answer), Ok(6));
        assert_eq!(verify(answer["txid"].as_str().unwrap(), &answer), Err(ProofError::Signature));
        // The third leaf's first sibling is itself.
        assert_eq!(answer["blocks"][0]["tx_branch"][0], json!(hex::encode(hash256(b"transaction two"))));
    }

    #[test]
    fn transaction_branches_cannot_be_shorter_or_longer_than_the_coinbases() {
        let mut short = chain(1);
        short["blocks"][0]["tx_branch"].as_array_mut().unwrap().pop();
        assert_eq!(check(&short), Err(ProofError::TransactionBranch));

        // A 64-byte transaction can be read as two child nodes; a longer branch can reach the same real root.
        let left = hash256(b"left child");
        let right = hash256(b"right child");
        let parent = merkle(left, &[right], 0).unwrap();
        let block = synthetic_block(PQBLOCK_HEIGHT, [0; 32], &height_prefix(PQBLOCK_HEIGHT), &[parent]);
        let cb_hash = hash256(&hex::decode(block["coinbase"].as_str().unwrap()).unwrap());
        let mut long = json!({"txid": display_hex(&parent), "height": PQBLOCK_HEIGHT, "tip": PQBLOCK_HEIGHT, "blocks": [block]});
        assert_eq!(check(&long), Ok(1));
        let header = hex::decode(long["blocks"][0]["header"].as_str().unwrap()).unwrap();
        assert_eq!(merkle(left, &[right, cb_hash], 2).unwrap().as_slice(), &header[36..68]);
        long["txid"] = json!(display_hex(&left));
        long["blocks"][0]["tx_index"] = json!(2);
        long["blocks"][0]["tx_branch"] = json!([hex::encode(right), hex::encode(cb_hash)]);
        assert_eq!(check(&long), Err(ProofError::TransactionBranch));
    }

    #[test]
    fn an_internal_merkle_node_is_not_a_transaction() {
        let mut answer = chain(6);
        let block = &answer["blocks"][0];
        let siblings = branch(block.get("tx_branch")).unwrap();
        let leaf = hash256(b"transaction two");
        let internal = merkle(leaf, &siblings[..1], 0).unwrap();
        let header = hex::decode(block["header"].as_str().unwrap()).unwrap();
        assert_eq!(merkle(internal, &siblings[1..], 1).unwrap().as_slice(), &header[36..68]);
        answer["txid"] = json!(display_hex(&internal));
        answer["blocks"][0]["tx_index"] = json!(1);
        answer["blocks"][0]["tx_branch"] = json!(siblings[1..].iter().map(hex::encode).collect::<Vec<_>>());
        assert_eq!(check(&answer), Err(ProofError::TransactionBranch));
    }

    #[test]
    fn duplicated_last_nodes_do_not_have_transaction_indices() {
        // Covers duplication at the leaf level and at an inner level.
        for (count, phantom) in [(2usize, 3u32), (4, 6), (5, 7), (6, 7)] {
            let others: Vec<_> = (0..count).map(|i| hash256(&i.to_le_bytes())).collect();
            let block = synthetic_block(PQBLOCK_HEIGHT, [0; 32], &height_prefix(PQBLOCK_HEIGHT), &others);
            let mut answer = json!({"txid": display_hex(others.last().unwrap()), "height": PQBLOCK_HEIGHT, "tip": PQBLOCK_HEIGHT, "blocks": [block]});
            assert_eq!(check(&answer), Ok(1));
            answer["blocks"][0]["tx_index"] = json!(phantom);
            assert_eq!(check(&answer), Err(ProofError::TransactionBranch));
        }
        let mut answer = chain(1);
        let depth = answer["blocks"][0]["coinbase_branch"].as_array().unwrap().len();
        answer["blocks"][0]["tx_index"] = json!(1u64 << depth);
        assert_eq!(check(&answer), Err(ProofError::TransactionBranch));
    }

    fn remine(block: &mut Value) {
        let mut header: [u8; 80] = hex::decode(block["header"].as_str().unwrap()).unwrap().try_into().unwrap();
        mine(&mut header);
        block["header"] = json!(hex::encode(header));
    }

    fn mutate_header(block: &mut Value, offset: usize) {
        let mut header = hex::decode(block["header"].as_str().unwrap()).unwrap();
        header[offset] ^= 1;
        block["header"] = json!(hex::encode(header));
        remine(block);
    }

    #[test]
    fn linkage_heights_work_and_both_inclusion_paths_are_required() {
        let good = chain(2);
        let mut a = good.clone();
        mutate_header(&mut a["blocks"][1], 4);
        assert_eq!(check(&a), Err(ProofError::Linkage));
        let mut a = good.clone();
        a["blocks"][1]["height"] = json!(PQBLOCK_HEIGHT + 2);
        assert_eq!(check(&a), Err(ProofError::Heights));
        let mut a = good.clone();
        a["height"] = json!(PQBLOCK_HEIGHT - 1);
        assert_eq!(check(&a), Err(ProofError::BeforeActivation));
        let mut a = good.clone();
        a["tip"] = json!(PQBLOCK_HEIGHT - 1);
        assert_eq!(check(&a), Err(ProofError::Heights));
        let mut a = good.clone();
        a["blocks"].as_array_mut().unwrap().pop();
        assert_eq!(check(&a), Err(ProofError::Heights));
        let mut a = chain(1);
        a["blocks"][0]["coinbase_branch"][0] = json!("ab".repeat(32));
        assert_eq!(check(&a), Err(ProofError::CoinbaseBranch));
        let mut a = chain(1);
        a["blocks"][0]["tx_branch"][0] = json!("ab".repeat(32));
        assert_eq!(check(&a), Err(ProofError::TransactionBranch));
        let mut a = chain(1);
        a["blocks"][0]["tx_index"] = json!(0);
        assert_eq!(check(&a), Err(ProofError::TransactionBranch));
        a["blocks"][0]["tx_index"] = json!(4);
        assert_eq!(check(&a), Err(ProofError::TransactionBranch));
        let mut a = chain(1);
        let mut header: [u8; 80] = hex::decode(a["blocks"][0]["header"].as_str().unwrap()).unwrap().try_into().unwrap();
        for nonce in 0..=u32::MAX {
            header[76..].copy_from_slice(&nonce.to_le_bytes());
            if !work(&header) { break; }
        }
        a["blocks"][0]["header"] = json!(hex::encode(header));
        assert_eq!(check(&a), Err(ProofError::Work));
        for offset in [0, 68] {
            let mut a = chain(1);
            mutate_header(&mut a["blocks"][0], offset);
            assert_eq!(check(&a), Err(ProofError::Signature));
        }
        let mut a = chain(1);
        mutate_header(&mut a["blocks"][0], 36);
        assert_eq!(check(&a), Err(ProofError::CoinbaseBranch));
        let mut a = chain(1);
        let h = PQBLOCK_HEIGHT;
        a["blocks"][0] = synthetic_block(h, [0; 32], &height_prefix(h + 1), &[]);
        assert_eq!(check(&a), Err(ProofError::Heights));
    }

    #[test]
    fn compact_targets_match_uint256_rules_and_byte_order() {
        for bits in [0, 0x0100_0001, 0x0180_0001, 0x2080_0001, 0x2300_0001, 0x2200_0100, 0x2101_0000] {
            assert_eq!(target(bits), None, "{bits:08x}");
        }
        assert_eq!(target(0x0101_0000).unwrap()[0], 1);
        assert_eq!(target(0x0201_0000).unwrap()[1], 1);
        assert_eq!(target(0x0301_0000).unwrap()[2], 1);
        assert_eq!(target(0x0401_0000).unwrap()[3], 1);
        assert_eq!(target(0x2100_ffff).unwrap()[31], 0xff);
        assert_eq!(target(0x2200_00ff).unwrap()[31], 0xff);
        let mut header = [0; 80];
        header[72..76].copy_from_slice(&0x0101_0000u32.to_le_bytes());
        assert!(!work(&header));
        let mut a = chain(1);
        for bits in [0u32, 0x2080_0001, 0x2300_0001, 0x0101_0000] {
            let mut header = hex::decode(a["blocks"][0]["header"].as_str().unwrap()).unwrap();
            header[72..76].copy_from_slice(&bits.to_le_bytes());
            a["blocks"][0]["header"] = json!(hex::encode(header));
            assert_eq!(check(&a), Err(ProofError::Work));
        }
    }

    #[test]
    fn commitment_form_is_exact_and_only_the_last_commitment_counts() {
        let good = commitment();
        assert!(signature(&good).is_ok());
        for n in [5, 75, 76, 255, 256, 65_535, 65_536] {
            let mut solution = SIGNET_HEADER.to_vec();
            solution.resize(n, 1);
            let mut script = good.clone();
            script.extend(push(&solution));
            assert!(signature(&script).is_ok(), "{n}");
            script.push(0);
            assert_eq!(signature(&script), Err(ProofError::Commitment));
        }
        for tail in [vec![0], vec![0x4f], push(SIGNET_HEADER), push(b"wrong"), vec![0x4c, 5, 0xec, 0xc7, 0xda, 0xa2, 1],
            vec![0x4d, 5, 0, 0xec, 0xc7, 0xda, 0xa2, 1], vec![0x4e, 5, 0, 0, 0, 0xec, 0xc7, 0xda, 0xa2, 1], vec![0x4e, 255, 255, 255, 255]] {
            let mut script = good.clone();
            script.extend(tail);
            assert_eq!(signature(&script), Err(ProofError::Commitment));
        }
        for i in [0, 1, 38, 39, 40, 41, 45] {
            let mut script = good.clone();
            script[i] ^= 1;
            assert_eq!(signature(&script), Err(ProofError::Commitment));
        }
        for len in [0, 6, 37, 38, 41, 45, good.len() - 1] {
            assert_eq!(signature(&good[..len]), Err(ProofError::Commitment));
        }
        let malformed = COMMITMENT.to_vec();
        let raw = coinbase(&height_prefix(PQBLOCK_HEIGHT), &[good.clone(), malformed.clone()]);
        let cb = Coinbase::parse(&raw, PQBLOCK_HEIGHT).unwrap();
        assert_eq!(signature(cb.script), Err(ProofError::Commitment));
        let raw = coinbase(&height_prefix(PQBLOCK_HEIGHT), &[malformed, good]);
        assert!(signature(Coinbase::parse(&raw, PQBLOCK_HEIGHT).unwrap().script).is_ok());
    }

    #[test]
    fn coinbase_serialization_is_legacy_canonical_and_bip34_exact() {
        let prefix = height_prefix(PQBLOCK_HEIGHT);
        for script in [vec![2, 0x20, 0x4e, 0], vec![0x4c, 2, 0x20, 0x4e], vec![3, 0x20, 0x4e, 0], height_prefix(PQBLOCK_HEIGHT + 1)] {
            // The first item is the right prefix followed by coinbase data.
            let raw = coinbase(&script, &[commitment()]);
            assert_eq!(Coinbase::parse(&raw, PQBLOCK_HEIGHT).is_ok(), script == vec![2, 0x20, 0x4e, 0]);
        }
        for h in [32_767, 32_768, 65_535, 8_388_607, 8_388_608, u32::MAX] {
            let raw = coinbase(&height_prefix(h), &[commitment()]);
            assert!(Coinbase::parse(&raw, h).is_ok());
        }
        let raw = coinbase(&prefix, &[commitment()]);
        for len in 0..raw.len() {
            assert!(Coinbase::parse(&raw[..len], PQBLOCK_HEIGHT).is_err());
        }
        for (offset, byte) in [(4, 0), (4, 2), (5, 1), (37, 0)] {
            let mut bad = raw.clone();
            bad[offset] = byte;
            assert!(Coinbase::parse(&bad, PQBLOCK_HEIGHT).is_err());
        }
        let mut bad = raw.clone();
        bad.push(0);
        assert!(Coinbase::parse(&bad, PQBLOCK_HEIGHT).is_err());
        let mut bad = raw.clone();
        bad.splice(4..5, [0xfd, 1, 0]);
        assert!(Coinbase::parse(&bad, PQBLOCK_HEIGHT).is_err());
        let mut bad = raw.clone();
        bad.splice(4..5, [0, 1, 1]);
        assert!(Coinbase::parse(&bad, PQBLOCK_HEIGHT).is_err());
        assert!(Coinbase::parse(&coinbase(&[1], &[commitment()]), PQBLOCK_HEIGHT).is_err());
        assert!(Coinbase::parse(&coinbase(&[1; 101], &[commitment()]), PQBLOCK_HEIGHT).is_err());
        let mut longest = prefix.clone();
        longest.resize(100, 0);
        assert!(Coinbase::parse(&coinbase(&longest, &[commitment()]), PQBLOCK_HEIGHT).is_ok());
        assert!(Coinbase::parse(&coinbase(&prefix, &[]), PQBLOCK_HEIGHT).is_err());
        let mut r = Reader { bytes: &[0xff, 255, 255, 255, 255, 255, 255, 255, 255], at: 0 };
        assert_eq!(r.size(MAX_COINBASE_BYTES), Err(ProofError::Bounds));
        for bytes in [&[0xfd, 1, 0][..], &[0xfe, 255, 0, 0, 0], &[0xff, 255, 255, 0, 0, 0, 0, 0, 0]] {
            assert_eq!(Reader { bytes, at: 0 }.size(MAX_COINBASE_BYTES), Err(ProofError::Coinbase));
        }
    }

    #[test]
    fn all_remote_lengths_counts_and_indices_are_bounded() {
        let good = chain(1);
        for (field, value) in [
            ("header", json!("00".repeat(81))),
            ("coinbase", json!("00".repeat(MAX_COINBASE_BYTES + 1))),
            ("coinbase_branch", json!(vec!["00".repeat(32); MAX_BRANCH + 1])),
            ("tx_branch", json!(vec!["00".repeat(32); MAX_BRANCH + 1])),
            ("coinbase_branch", json!(["00".repeat(33)])),
            ("tx_branch", json!(["00".repeat(33)])),
        ] {
            let mut a = good.clone();
            a["blocks"][0][field] = value;
            assert_eq!(check(&a), Err(ProofError::Bounds), "{field}");
        }
        let mut a = good.clone();
        a["blocks"] = json!(vec![a["blocks"][0].clone(); REQUIRED_BLOCKS as usize + 1]);
        assert_eq!(check(&a), Err(ProofError::Bounds));
        a["blocks"] = json!([]);
        assert_eq!(check(&a), Err(ProofError::Heights));
        for field in ["height", "tip"] {
            let mut a = good.clone();
            a[field] = json!(u64::from(u32::MAX) + 1);
            assert_eq!(check(&a), Err(ProofError::Malformed));
        }
        for value in [json!(-1), json!(u64::from(u32::MAX) + 1), json!("0")] {
            let mut a = good.clone();
            a["blocks"][0]["tx_index"] = value;
            assert_eq!(check(&a), Err(ProofError::Malformed));
        }
        assert!(merkle([0; 32], &[[1; 32]; MAX_BRANCH], u32::MAX).is_some());
        assert!(branch(Some(&json!(vec!["00".repeat(32); MAX_BRANCH]))).is_ok());
        assert_eq!(bytes(Some(&json!("00".repeat(MAX_COINBASE_BYTES))), MAX_COINBASE_BYTES).unwrap().len(), MAX_COINBASE_BYTES);
        assert_eq!(Reader { bytes: &[100], at: 0 }.size(100), Ok(100));
        assert_eq!(Reader { bytes: &[101], at: 0 }.size(100), Err(ProofError::Bounds));
        let mut scripts = [commitment(), vec![0; MAX_COINBASE_BYTES]];
        let overhead = coinbase(&height_prefix(PQBLOCK_HEIGHT), &scripts).len() - MAX_COINBASE_BYTES;
        scripts[1].truncate(MAX_COINBASE_BYTES - overhead);
        let mut raw = coinbase(&height_prefix(PQBLOCK_HEIGHT), &scripts);
        assert_eq!(raw.len(), MAX_COINBASE_BYTES);
        assert!(Coinbase::parse(&raw, PQBLOCK_HEIGHT).is_ok());
        raw.push(0);
        assert!(matches!(Coinbase::parse(&raw, PQBLOCK_HEIGHT), Err(ProofError::Bounds)));
        let mut r = Reader { bytes: &[], at: usize::MAX };
        assert_eq!(r.take(1), Err(ProofError::Bounds));
        let mut r = Reader { bytes: &[0xfe, 8, 178, 1, 0], at: 0 };
        assert_eq!(r.size(MAX_COINBASE_BYTES / 9), Err(ProofError::Bounds));
        for (field, value) in [("header", json!("00".repeat(79))), ("header", json!("z".repeat(160))),
            ("coinbase_branch", json!(["0"])), ("tx_branch", json!(["00".repeat(31)]))] {
            let mut a = good.clone();
            a["blocks"][0][field] = value;
            assert_eq!(check(&a), Err(ProofError::Malformed));
        }
        assert_eq!(verify(&"a".repeat(65), &good), Err(ProofError::Malformed));
        assert_eq!(verify(&"a".repeat(64), &good), Err(ProofError::Malformed));
        let mut a = chain(2);
        a["blocks"][1]["tx_branch"] = json!([]);
        assert_eq!(check(&a), Err(ProofError::Malformed));
        // The last height does not rely on h + 5, which could overflow.
        let h = u32::MAX;
        let block = synthetic_block(h, [0; 32], &height_prefix(h), &[]);
        let txid = display_hex(&hash256(&hex::decode(block["coinbase"].as_str().unwrap()).unwrap()));
        let a = json!({"txid": txid, "height": h, "tip": h, "blocks": [block]});
        assert_eq!(check(&a), Ok(1));
    }

    #[test]
    fn missing_or_mistyped_proof_fields_are_not_answers() {
        let good = chain(1);
        let txid = good["txid"].as_str().unwrap();
        for field in ["txid", "height", "tip", "blocks"] {
            let mut a = good.clone();
            a.as_object_mut().unwrap().remove(field);
            assert_eq!(verify_with_key(txid, &a, &key().public), Err(ProofError::Malformed), "{field}");
        }
        for field in ["height", "header", "coinbase", "coinbase_branch", "tx_index", "tx_branch"] {
            for replacement in [None, Some(Value::Null), Some(json!({}))] {
                let mut a = good.clone();
                let block = a["blocks"][0].as_object_mut().unwrap();
                if let Some(value) = replacement { block.insert(field.into(), value); }
                else { block.remove(field); }
                assert_eq!(check(&a), Err(ProofError::Malformed), "{field}");
            }
        }
    }
}
