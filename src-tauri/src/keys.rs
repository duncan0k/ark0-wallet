//! The wallet's keys: the keys of each template's leaves, from one secret.
//!
//! A wallet made here holds 32 bytes of entropy, written down as 24 BIP-39 words. The words give the
//! standard 64-byte BIP-39 seed (no passphrase), and HKDF-SHA-512 derives each key from that seed under a
//! label that names this wallet, the derivation's version, the network, the algorithm, the template, the
//! account, the chain (receiving or change), the index and an attempt counter, each field with a two-byte
//! length in front. The network is the SHA-256 of the signet challenge: every signet shares one genesis
//! block and the `tb` prefix; the challenge tells them apart. Each template has keys of its own, so the
//! classic, the post-quantum and the mixed address share none. tools/derivation/derive.py computes the
//! same with Python's standard library alone, and tests/vectors/derivation.json holds its results.
//!
//! The pq2 template ("e2-pq2") is the one template with more than one output: every pq2 address has two
//! keys of its own, at account 0 and a fresh index, on the receiving chain (0) or the change chain (1). Its
//! ML-DSA-44 key is KeyGen on 32 bytes of HKDF output, its SLH-DSA-SHA2-128s key slh_keygen_internal on 48
//! (SK.seed, SK.prf and PK.seed, 16 bytes each); both at attempt 0 and the same chain and index.
//!
//! This is not BIP-32: the 24 words open this wallet only. Typed into another wallet they give other
//! keys, and on an Ethereum wallet they would make a hot wallet of the words.
//!
//! A wallet of the Ark-0 web wallet holds a 32-byte seed, written down as an `ark0w1-…` backup code. Its
//! keys are derived as the web wallet derives them (keys.ts): the BIP-340 key is HMAC-SHA256 keyed with
//! `ark0-wallet v1 schnorr` over the seed and a counter byte, for the first counter from 0 that gives a
//! valid key; the ML-DSA-44 key is KeyGen on HMAC-SHA256 keyed with `ark0-wallet v1 mldsa44` over the seed.
//! As in the web wallet, its three templates share these two keys. It has no pq2: its derivation has no
//! index, and every pq2 output needs keys of its own.
use crate::p2mr::{Kind, Template, MLDSA44_CONTEXT, SLHDSA128S_CONTEXT};
use crate::{mldsa, slhdsa};
use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{schnorr, Keypair, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The signet challenge of Ark-0: a 1-of-1 multisig of its block signing key.
pub const ARK0_CHALLENGE: &str = "5121026fc5d8e79a9fbc8bc3dea07d82641d16717ce0b000c13c512d8e8c1788c6e5da51ae";
pub const WORDS: usize = 24;
const HKDF_SALT: &[u8] = b"ark0-wallet key derivation v1";
const LABEL_WALLET: &[u8] = b"ark0-wallet";
const LABEL_VERSION: &[u8] = b"v1";
const LEGACY_SCHNORR_LABEL: &[u8] = b"ark0-wallet v1 schnorr";
const LEGACY_MLDSA44_LABEL: &[u8] = b"ark0-wallet v1 mldsa44";
const BACKUP_PREFIX: &str = "ark0w1-";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyError {
    /// Not 24 words of the BIP-39 English list with a matching checksum.
    InvalidPhrase,
    /// Not an `ark0w1-` code, or its checksum does not match.
    InvalidBackupCode,
    /// The system could not provide random numbers for a new wallet.
    Randomness,
    /// No valid BIP-340 key within 256 attempts (each misses with a probability of about 2^-128).
    NoKey,
    /// A Schnorr signature could not be made, or did not verify.
    Schnorr,
    Mldsa44,
    Slhdsa128s,
    /// A wallet restored from a backup code has no pq2 keys.
    Pq2Unavailable,
}

/// The two chains of pq2 addresses.
pub const RECEIVE_CHAIN: u32 = 0;
pub const CHANGE_CHAIN: u32 = 1;
/// Indices are hardened-style u32 values; the wallet never goes near the top.
pub const MAX_PQ2_INDEX: u32 = 0x7fff_ffff;

/// 32 secret bytes, hex in the vault's encrypted payload, wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(pub Zeroizing<[u8; 32]>);

impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Zeroizing::new(hex::encode(*self.0)))
    }
}

impl<'de> serde::Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text.as_str(), bytes.as_mut()).map_err(serde::de::Error::custom)?;
        Ok(SecretBytes(bytes))
    }
}

/// The secret a vault holds.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Secret {
    /// 24 words.
    Bip39 { entropy: SecretBytes },
    /// A wallet of the Ark-0 web wallet, restored from its backup code.
    Legacy { seed: SecretBytes },
}

impl Secret {
    pub fn new_bip39() -> Result<Self, KeyError> {
        Self::new_bip39_with(getrandom::fill)
    }

    fn new_bip39_with<E>(fill: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, KeyError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        fill(entropy.as_mut()).map_err(|_| KeyError::Randomness)?;
        Ok(Secret::Bip39 { entropy: SecretBytes(entropy) })
    }

    /// 24 words of the English list, in any case and spacing.
    pub fn from_phrase(phrase: &str) -> Result<Self, KeyError> {
        // Built in place, so that no unwiped copy of the words is left behind.
        let mut normalized = Zeroizing::new(String::with_capacity(phrase.len()));
        for word in phrase.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.extend(word.chars().flat_map(char::to_lowercase));
        }
        let mnemonic =
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized).map_err(|_| KeyError::InvalidPhrase)?;
        if mnemonic.word_count() != WORDS {
            return Err(KeyError::InvalidPhrase);
        }
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&entropy[..len]);
        entropy.zeroize();
        Ok(Secret::Bip39 { entropy: SecretBytes(out) })
    }

    /// `ark0w1-` + the seed in hex + `-` + the first 4 bytes of its SHA-256 in hex; spaces, line breaks and
    /// letter case do not matter.
    pub fn from_backup_code(text: &str) -> Result<Self, KeyError> {
        // Built in place, so that no unwiped copy of the code is left behind.
        let mut compact = Zeroizing::new(String::with_capacity(text.len()));
        compact.extend(text.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase));
        let rest = compact.strip_prefix(BACKUP_PREFIX).ok_or(KeyError::InvalidBackupCode)?;
        let (seed_hex, check) = rest.split_once('-').ok_or(KeyError::InvalidBackupCode)?;
        if seed_hex.len() != 64 || check.len() != 8 || !seed_hex.bytes().chain(check.bytes()).all(|b| b.is_ascii_hexdigit()) {
            return Err(KeyError::InvalidBackupCode);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(seed_hex, seed.as_mut()).map_err(|_| KeyError::InvalidBackupCode)?;
        if backup_checksum(&seed) != check {
            return Err(KeyError::InvalidBackupCode);
        }
        Ok(Secret::Legacy { seed: SecretBytes(seed) })
    }

    /// The words, or the backup code, as the user wrote them down.
    pub fn recovery_text(&self) -> Zeroizing<String> {
        match self {
            Secret::Bip39 { entropy } => {
                let mnemonic =
                    bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy.0.as_ref()).expect("32 bytes of entropy");
                Zeroizing::new(mnemonic.words().collect::<Vec<_>>().join(" "))
            }
            Secret::Legacy { seed } => {
                let seed_hex = Zeroizing::new(hex::encode(*seed.0));
                let mut code = Zeroizing::new(String::with_capacity(BACKUP_PREFIX.len() + 64 + 9));
                code.push_str(BACKUP_PREFIX);
                code.push_str(&seed_hex);
                code.push('-');
                code.push_str(&backup_checksum(&seed.0));
                code
            }
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self, Secret::Legacy { .. })
    }
}

/// Whether the text starts the way a backup code does, in any letter case and after any leading space.
pub fn looks_like_backup_code(text: &str) -> bool {
    let tag = BACKUP_PREFIX.trim_end_matches('-');
    text.trim_start().get(..tag.len()).is_some_and(|start| start.eq_ignore_ascii_case(tag))
}

fn backup_checksum(seed: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(seed)[..4])
}

/// The BIP-39 English word list, for the restore form's suggestions.
pub fn word_list() -> &'static [&'static str; 2048] {
    bip39::Language::English.word_list()
}

/// The network a key belongs to: SHA-256 of the signet challenge script.
pub fn network_id(challenge_hex: &str) -> [u8; 32] {
    Sha256::digest(hex::decode(challenge_hex).expect("a hex challenge")).into()
}

/// The HKDF info: every field with a two-byte big-endian length in front.
fn info(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&u16::try_from(f.len()).expect("a field of at most 32 bytes").to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// The template field of the HKDF info: the P2MR leaf version (0xc0, 0xe0 or 0xe2) and what the template
/// holds. Each name stands for one tree for good; another tree gets another name.
fn template_label(kind: Kind) -> &'static [u8] {
    match kind {
        Kind::Schnorr => b"c0-schnorr",
        Kind::Mldsa44 => b"c0-mldsa44",
        Kind::Mixed => b"e0-hybrid",
        Kind::Pq2 => b"e2-pq2",
    }
}

/// The HKDF info of one key at account 0 and the given chain and index.
fn key_info_at(network: &[u8; 32], algorithm: &[u8], kind: Kind, chain: u32, index: u32, attempt: u8) -> Vec<u8> {
    let account = 0u32;
    info(&[
        LABEL_WALLET,
        LABEL_VERSION,
        network,
        algorithm,
        template_label(kind),
        &account.to_be_bytes(),
        &chain.to_be_bytes(),
        &index.to_be_bytes(),
        &[attempt],
    ])
}

/// The HKDF info of one key of the three fixed templates. Account 0, the receiving chain and index 0: the
/// one key of each of their leaves; the fields are there so that more never collide with it.
fn key_info(network: &[u8; 32], algorithm: &[u8], kind: Kind, attempt: u8) -> Vec<u8> {
    key_info_at(network, algorithm, kind, 0, 0, attempt)
}

/// The standard BIP-39 seed of 24 words, without a passphrase.
fn bip39_seed(entropy: &[u8; 32]) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy).map_err(|_| KeyError::InvalidPhrase)?;
    Ok(Zeroizing::new(mnemonic.to_seed_normalized("")))
}

/// SHA-512 of `parts`, over sha2's core type itself, its output written straight into `out`. The core
/// state and the block buffer are wiped when they are dropped (sha2's zeroize feature). The `Sha512`
/// wrapper is not used: it finalises into a plain array of its own and copies that out.
fn sha512_into(parts: &[&[u8]], out: &mut [u8; 64]) {
    use sha2::block_api::Sha512VarCore;
    use sha2::digest::block_api::{Buffer, UpdateCore, VariableOutputCore};
    let mut core = Sha512VarCore::new(64).expect("SHA-512 has a 64-byte output");
    let mut buffer = Buffer::<Sha512VarCore>::default();
    for p in parts {
        buffer.digest_blocks(p, |blocks| core.update_blocks(blocks));
    }
    let out: &mut sha2::digest::Output<Sha512VarCore> = (&mut out[..]).try_into().expect("64 bytes");
    core.finalize_variable_core(&mut buffer, out);
}

/// HMAC-SHA-512 (RFC 2104) of `parts` under `key`, into `out`, computed here over sha2 so that every
/// intermediate is wiped: the key block, both pads (key xor ipad, key xor opad) and the inner hash live in
/// buffers wiped on drop, and both hash states are wiped when they are dropped.
fn hmac_sha512_into(key: &[u8], parts: &[&[u8]], out: &mut [u8; 64]) {
    const BLOCK: usize = 128;
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        let mut hashed = Zeroizing::new([0u8; 64]);
        sha512_into(&[key], &mut hashed);
        block[..64].copy_from_slice(&hashed[..]);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0u8; BLOCK]);
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x36;
    }
    let mut inner = Zeroizing::new([0u8; 64]);
    let mut inner_parts: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    inner_parts.push(&pad[..]);
    inner_parts.extend_from_slice(parts);
    sha512_into(&inner_parts, &mut inner);
    drop(inner_parts);
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x5c;
    }
    sha512_into(&[&pad[..], &inner[..]], out);
}

/// HKDF-SHA-512 (RFC 5869) under the wallet's salt, filling `out` (at most 255 blocks of 64 bytes). The
/// pseudorandom key and every block of Expand are kept in buffers that are wiped when they are dropped.
fn hkdf_sha512(seed: &[u8; 64], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * 64, "HKDF-SHA-512 gives at most 255 blocks");
    let mut prk = Zeroizing::new([0u8; 64]);
    hmac_sha512_into(HKDF_SALT, &[seed], &mut prk);
    let mut block = Zeroizing::new([0u8; 64]);
    for (i, chunk) in out.chunks_mut(64).enumerate() {
        let counter = [(i + 1) as u8];
        let previous = Zeroizing::new(*block);
        let parts: [&[u8]; 3] = if i == 0 { [&[], info, &counter] } else { [&previous[..], info, &counter] };
        hmac_sha512_into(prk.as_ref(), &parts, &mut block);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// 32 bytes for one key.
fn hkdf32(seed: &[u8; 64], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf_sha512(seed, label, out.as_mut());
    out
}

/// 48 bytes for one SLH-DSA-SHA2-128s key.
fn hkdf48(seed: &[u8; 64], label: &[u8]) -> Zeroizing<[u8; 48]> {
    let mut out = Zeroizing::new([0u8; 48]);
    hkdf_sha512(seed, label, out.as_mut());
    out
}

/// The ML-DSA-44 KeyGen seed of the pq2 output at this chain and index.
fn pq2_mldsa44_seed(seed: &[u8; 64], network: &[u8; 32], chain: u32, index: u32) -> Zeroizing<[u8; 32]> {
    hkdf32(seed, &key_info_at(network, b"mldsa44", Kind::Pq2, chain, index, 0))
}

/// The SLH-DSA-SHA2-128s seed (SK.seed, SK.prf, PK.seed) of the pq2 output at this chain and index.
fn pq2_slhdsa128s_seed(seed: &[u8; 64], network: &[u8; 32], chain: u32, index: u32) -> Zeroizing<[u8; 48]> {
    hkdf48(seed, &key_info_at(network, b"slhdsa128s", Kind::Pq2, chain, index, 0))
}

/// A template's BIP-340 key of a 24-word wallet: the first attempt that gives a valid secret key.
fn bip39_schnorr(seed: &[u8; 64], network: &[u8; 32], kind: Kind) -> Result<Keypair, KeyError> {
    (0..=255u8)
        .find_map(|attempt| Keypair::from_secret_bytes(*hkdf32(seed, &key_info(network, b"schnorr", kind, attempt))).ok())
        .ok_or(KeyError::NoKey)
}

/// A template's ML-DSA-44 KeyGen seed of a 24-word wallet.
fn bip39_mldsa44_seed(seed: &[u8; 64], network: &[u8; 32], kind: Kind) -> Zeroizing<[u8; 32]> {
    hkdf32(seed, &key_info(network, b"mldsa44", kind, 0))
}

/// The BIP-340 key and the ML-DSA-44 KeyGen seed of a wallet of the Ark-0 web wallet.
fn legacy_material(seed: &[u8; 32]) -> Result<(Keypair, Zeroizing<[u8; 32]>), KeyError> {
    let hmac = |label: &[u8], parts: &[&[u8]]| -> Zeroizing<[u8; 32]> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(label).expect("HMAC takes a key of any length");
        for p in parts {
            mac.update(p);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        let tag = mac.finalize();
        out.copy_from_slice(&tag.as_bytes()[..]);
        out
    };
    let schnorr = (0..=255u8)
        .find_map(|counter| Keypair::from_secret_bytes(*hmac(LEGACY_SCHNORR_LABEL, &[seed, &[counter]])).ok())
        .ok_or(KeyError::NoKey)?;
    Ok((schnorr, hmac(LEGACY_MLDSA44_LABEL, &[seed])))
}

/// A BIP-340 key pair; the secret is erased when it is dropped.
struct SchnorrKey {
    pair: Keypair,
    xonly: XOnlyPublicKey,
}

impl SchnorrKey {
    fn new(pair: Keypair) -> Self {
        let (xonly, _) = pair.x_only_public_key();
        SchnorrKey { pair, xonly }
    }
}

impl Drop for SchnorrKey {
    fn drop(&mut self) {
        self.pair.non_secure_erase();
    }
}

/// The keys of the three templates: a BIP-340 key for each Schnorr leaf and an ML-DSA-44 key pair (which
/// wipes itself) for each ML-DSA-44 leaf.
pub struct Keys {
    schnorr: SchnorrKey,
    mldsa44: mldsa::KeyPair,
    mixed_schnorr: SchnorrKey,
    mixed_mldsa44: mldsa::KeyPair,
    /// The BIP-39 seed of a 24-word wallet, from which pq2 keys are derived when they are needed; None for
    /// a backup code's wallet. Wiped when dropped.
    pq2_seed: Option<Zeroizing<[u8; 64]>>,
}

/// The two key pairs of one pq2 output (both wipe their secrets).
pub struct Pq2Keys {
    mldsa44: mldsa::KeyPair,
    slhdsa128s: slhdsa::KeyPair,
}

impl Pq2Keys {
    pub fn template(&self) -> Template {
        Template::pq2(&self.mldsa44.public, &self.slhdsa128s.public)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mldsa44_public_key(&self) -> &[u8; mldsa::PUBLIC_KEY_LEN] {
        &self.mldsa44.public
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn slhdsa128s_public_key(&self) -> &[u8; slhdsa::PUBLIC_KEY_LEN] {
        &self.slhdsa128s.public
    }

    /// ML-DSA-44 (hedged) with the key of leaf A, checked before it is returned.
    pub fn sign_mldsa44(&self, message: &[u8; 32]) -> Result<[u8; mldsa::SIGNATURE_LEN], KeyError> {
        let signature = mldsa::sign(message, MLDSA44_CONTEXT, &self.mldsa44.secret).map_err(|_| KeyError::Mldsa44)?;
        checked(&self.mldsa44, message, signature)
    }

    /// SLH-DSA-SHA2-128s (hedged: 16 bytes of fresh randomness) with the key of leaf B and
    /// OP_CHECKSLHDSA128S's context string, checked before it is returned.
    pub fn sign_slhdsa128s(&self, message: &[u8; 32]) -> Result<Box<[u8; slhdsa::SIGNATURE_LEN]>, KeyError> {
        let signature = slhdsa::sign(message, SLHDSA128S_CONTEXT, &self.slhdsa128s.secret).map_err(|_| KeyError::Slhdsa128s)?;
        checked_slh(&self.slhdsa128s, message, signature)
    }

    #[cfg(test)]
    pub(crate) fn sign_slhdsa128s_deterministic(&self, message: &[u8; 32]) -> Box<[u8; slhdsa::SIGNATURE_LEN]> {
        let signature = slhdsa::sign_known_answer(message, SLHDSA128S_CONTEXT, &self.slhdsa128s.secret).expect("signs");
        checked_slh(&self.slhdsa128s, message, signature).expect("verifies")
    }

    #[cfg(test)]
    pub(crate) fn sign_slhdsa128s_with(&self, message: &[u8; 32], randomness: &[u8; 16]) -> Box<[u8; slhdsa::SIGNATURE_LEN]> {
        let signature = slhdsa::sign_with_randomness(message, SLHDSA128S_CONTEXT, &self.slhdsa128s.secret, randomness).expect("signs");
        checked_slh(&self.slhdsa128s, message, signature).expect("verifies")
    }

    #[cfg(test)]
    pub(crate) fn sign_mldsa44_deterministic(&self, message: &[u8; 32]) -> [u8; mldsa::SIGNATURE_LEN] {
        let signature = mldsa::sign_deterministic(message, MLDSA44_CONTEXT, &self.mldsa44.secret).expect("signs");
        checked(&self.mldsa44, message, signature).expect("verifies")
    }

    /// From the two keygen seeds themselves (test vectors of other implementations).
    #[cfg(test)]
    pub(crate) fn from_seeds(mldsa44_seed: &[u8; 32], slhdsa128s_seed: &[u8; 48]) -> Pq2Keys {
        Pq2Keys {
            mldsa44: mldsa::keypair_from_seed(mldsa44_seed).unwrap(),
            slhdsa128s: slhdsa::keypair_from_seed(slhdsa128s_seed).unwrap(),
        }
    }
}

impl Keys {
    pub fn from_secret(secret: &Secret) -> Result<Keys, KeyError> {
        let keypair = |seed: &[u8; 32]| mldsa::keypair_from_seed(seed).map_err(|_| KeyError::Mldsa44);
        match secret {
            Secret::Bip39 { entropy } => {
                let seed = bip39_seed(&entropy.0)?;
                let network = network_id(ARK0_CHALLENGE);
                Ok(Keys {
                    schnorr: SchnorrKey::new(bip39_schnorr(&seed, &network, Kind::Schnorr)?),
                    mldsa44: keypair(&bip39_mldsa44_seed(&seed, &network, Kind::Mldsa44))?,
                    mixed_schnorr: SchnorrKey::new(bip39_schnorr(&seed, &network, Kind::Mixed)?),
                    mixed_mldsa44: keypair(&bip39_mldsa44_seed(&seed, &network, Kind::Mixed))?,
                    pq2_seed: Some(seed),
                })
            }
            Secret::Legacy { seed } => {
                let (schnorr, mldsa_seed) = legacy_material(&seed.0)?;
                Ok(Keys {
                    schnorr: SchnorrKey::new(schnorr),
                    mldsa44: keypair(&mldsa_seed)?,
                    mixed_schnorr: SchnorrKey::new(schnorr),
                    mixed_mldsa44: keypair(&mldsa_seed)?,
                    pq2_seed: None,
                })
            }
        }
    }

    /// Whether this wallet has pq2 keys: only a 24-word wallet does.
    pub fn has_pq2(&self) -> bool {
        self.pq2_seed.is_some()
    }

    /// The two key pairs of the pq2 output at this chain (0 receiving, 1 change) and index.
    pub fn pq2(&self, chain: u32, index: u32) -> Result<Pq2Keys, KeyError> {
        let seed = self.pq2_seed.as_ref().ok_or(KeyError::Pq2Unavailable)?;
        if chain > CHANGE_CHAIN || index > MAX_PQ2_INDEX {
            return Err(KeyError::Pq2Unavailable);
        }
        let network = network_id(ARK0_CHALLENGE);
        let mldsa44 = mldsa::keypair_from_seed(&pq2_mldsa44_seed(seed, &network, chain, index)).map_err(|_| KeyError::Mldsa44)?;
        let slhdsa128s = slhdsa::keypair_from_seed(&pq2_slhdsa128s_seed(seed, &network, chain, index)).map_err(|_| KeyError::Slhdsa128s)?;
        Ok(Pq2Keys { mldsa44, slhdsa128s })
    }

    /// The key of a template's Schnorr leaf (the post-quantum template has none and is never asked).
    fn schnorr_key(&self, kind: Kind) -> &SchnorrKey {
        if kind == Kind::Mixed {
            &self.mixed_schnorr
        } else {
            &self.schnorr
        }
    }

    /// The key of a template's ML-DSA-44 leaf (the classic template has none and is never asked).
    fn mldsa44_key(&self, kind: Kind) -> &mldsa::KeyPair {
        if kind == Kind::Mixed {
            &self.mixed_mldsa44
        } else {
            &self.mldsa44
        }
    }

    #[cfg(test)]
    pub(crate) fn xonly(&self, kind: Kind) -> [u8; 32] {
        self.schnorr_key(kind).xonly.to_byte_array()
    }

    #[cfg(test)]
    pub(crate) fn mldsa44_public_key(&self, kind: Kind) -> &[u8; mldsa::PUBLIC_KEY_LEN] {
        &self.mldsa44_key(kind).public
    }

    /// A template of the three with one output, made from its own keys. pq2 outputs come from `pq2`, never
    /// from here: asked for one, this answers with the tree of all-zero keys, which no key signs for.
    pub fn template(&self, kind: Kind) -> Template {
        match kind {
            Kind::Schnorr => Template::schnorr(&self.schnorr.xonly.to_byte_array()),
            Kind::Mldsa44 => Template::mldsa44(&self.mldsa44.public),
            Kind::Mixed => Template::mixed(&self.mixed_schnorr.xonly.to_byte_array(), &self.mixed_mldsa44.public),
            Kind::Pq2 => Template::pq2(&[0u8; mldsa::PUBLIC_KEY_LEN], &[0u8; slhdsa::PUBLIC_KEY_LEN]),
        }
    }

    /// BIP-340 with the key of a template's Schnorr leaf, over a 32-byte signature message, with fresh
    /// auxiliary randomness, checked before it is returned.
    pub fn sign_schnorr(&self, kind: Kind, message: &[u8; 32]) -> Result<[u8; 64], KeyError> {
        let mut aux = [0u8; 32];
        getrandom::fill(&mut aux).map_err(|_| KeyError::Schnorr)?;
        self.sign_schnorr_with(kind, message, &aux)
    }

    pub(crate) fn sign_schnorr_with(&self, kind: Kind, message: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], KeyError> {
        let key = self.schnorr_key(kind);
        let signature = schnorr::sign_with_aux_rand(message, &key.pair, aux);
        schnorr::verify(&signature, message, &key.xonly).map_err(|_| KeyError::Schnorr)?;
        Ok(signature.to_byte_array())
    }

    /// ML-DSA-44 (hedged) with the key of a template's ML-DSA-44 leaf, over a 32-byte signature message with
    /// OP_CHECKMLDSA44's context string, checked before it is returned.
    pub fn sign_mldsa44(&self, kind: Kind, message: &[u8; 32]) -> Result<[u8; mldsa::SIGNATURE_LEN], KeyError> {
        let key = self.mldsa44_key(kind);
        let signature = mldsa::sign(message, MLDSA44_CONTEXT, &key.secret).map_err(|_| KeyError::Mldsa44)?;
        checked(key, message, signature)
    }

    #[cfg(test)]
    pub(crate) fn sign_mldsa44_deterministic(&self, kind: Kind, message: &[u8; 32]) -> [u8; mldsa::SIGNATURE_LEN] {
        let key = self.mldsa44_key(kind);
        let signature = mldsa::sign_deterministic(message, MLDSA44_CONTEXT, &key.secret).expect("signs");
        checked(key, message, signature).expect("verifies")
    }
}

/// A fresh SLH-DSA signature, verified before it is used.
fn checked_slh(key: &slhdsa::KeyPair, message: &[u8; 32], signature: Box<[u8; slhdsa::SIGNATURE_LEN]>) -> Result<Box<[u8; slhdsa::SIGNATURE_LEN]>, KeyError> {
    if slhdsa::verify(&signature, message, SLHDSA128S_CONTEXT, &key.public) {
        Ok(signature)
    } else {
        Err(KeyError::Slhdsa128s)
    }
}

/// A fresh ML-DSA-44 signature, verified before it is used.
fn checked(key: &mldsa::KeyPair, message: &[u8; 32], signature: [u8; mldsa::SIGNATURE_LEN]) -> Result<[u8; mldsa::SIGNATURE_LEN], KeyError> {
    if mldsa::verify(&signature, message, MLDSA44_CONTEXT, &key.public) {
        Ok(signature)
    } else {
        Err(KeyError::Mldsa44)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha512;
    use crate::p2mr::tests::{h, vectors};

    fn bip39(entropy: [u8; 32]) -> Secret {
        Secret::Bip39 { entropy: SecretBytes(Zeroizing::new(entropy)) }
    }

    fn kind_of(template: &str) -> Kind {
        match template {
            "c0-schnorr" => Kind::Schnorr,
            "c0-mldsa44" => Kind::Mldsa44,
            "e0-hybrid" => Kind::Mixed,
            other => panic!("unknown template {other}"),
        }
    }

    #[test]
    fn the_derivation_matches_an_independent_computation() {
        // tools/derivation/derive.py: Python's hashlib and hmac alone (PBKDF2 for the BIP-39 seed, RFC 5869
        // by hand). A change here strands every wallet made so far.
        let v: serde_json::Value = serde_json::from_str(include_str!("../tests/vectors/derivation.json")).unwrap();
        let network = network_id(ARK0_CHALLENGE);
        assert_eq!(hex::encode(network), v["network_id"].as_str().unwrap());
        assert_eq!(HKDF_SALT, v["salt"].as_str().unwrap().as_bytes());
        for w in v["wallets"].as_array().unwrap() {
            let entropy: [u8; 32] = h(&w["entropy"]).try_into().unwrap();
            assert_eq!(bip39(entropy).recovery_text().as_str(), w["phrase"].as_str().unwrap());
            let seed = bip39_seed(&entropy).unwrap();
            assert_eq!(hex::encode(*seed), w["bip39_seed"].as_str().unwrap());
            for k in w["keys"].as_array().unwrap() {
                let kind = kind_of(k["template"].as_str().unwrap());
                let algorithm = k["algorithm"].as_str().unwrap();
                let attempt = k["attempt"].as_u64().unwrap() as u8;
                assert_eq!(hex::encode(key_info(&network, algorithm.as_bytes(), kind, attempt)), k["info"].as_str().unwrap());
                let got = match algorithm {
                    "schnorr" => hex::encode(bip39_schnorr(&seed, &network, kind).unwrap().to_secret_bytes()),
                    _ => hex::encode(*bip39_mldsa44_seed(&seed, &network, kind)),
                };
                let want = k.get("secret_key").or(k.get("keygen_seed")).and_then(|x| x.as_str()).unwrap();
                assert_eq!(got, want, "{} {}", k["template"], algorithm);
            }
        }
        // pq2: both keys of each output at its chain and index, their public keys and the address.
        let mut rows = 0;
        for w in v["wallets"].as_array().unwrap() {
            let entropy: [u8; 32] = h(&w["entropy"]).try_into().unwrap();
            let seed = bip39_seed(&entropy).unwrap();
            let keys = Keys::from_secret(&bip39(entropy)).unwrap();
            for r in w["pq2"].as_array().unwrap() {
                let (chain, index) = (r["chain"].as_u64().unwrap() as u32, r["index"].as_u64().unwrap() as u32);
                assert_eq!((r["template"].as_str(), r["account"].as_u64(), r["attempt"].as_u64()), (Some("e2-pq2"), Some(0), Some(0)));
                let ml_info = key_info_at(&network, b"mldsa44", Kind::Pq2, chain, index, 0);
                let slh_info = key_info_at(&network, b"slhdsa128s", Kind::Pq2, chain, index, 0);
                // Design section 8.2: 89 and 92 bytes, under the 110 the rescue statement takes.
                assert_eq!((ml_info.len(), slh_info.len()), (89, 92));
                assert_eq!(hex::encode(&ml_info), r["mldsa44"]["info"].as_str().unwrap());
                assert_eq!(hex::encode(&slh_info), r["slhdsa128s"]["info"].as_str().unwrap());
                assert_eq!(hex::encode(*pq2_mldsa44_seed(&seed, &network, chain, index)), r["mldsa44"]["keygen_seed"].as_str().unwrap());
                assert_eq!(hex::encode(*pq2_slhdsa128s_seed(&seed, &network, chain, index)), r["slhdsa128s"]["keygen_seed"].as_str().unwrap());
                let pair = keys.pq2(chain, index).unwrap();
                assert_eq!(hex::encode(Sha256::digest(pair.mldsa44_public_key())), r["mldsa44"]["public_key_sha256"].as_str().unwrap());
                assert_eq!(hex::encode(pair.slhdsa128s_public_key()), r["slhdsa128s"]["public_key"].as_str().unwrap());
                assert_eq!(hex::encode(Sha256::digest(pair.slhdsa128s_public_key())), r["slhdsa128s"]["public_key_sha256"].as_str().unwrap());
                assert_eq!(pair.template().address, r["address"].as_str().unwrap(), "chain {chain} index {index}");
                rows += 1;
            }
        }
        assert_eq!(rows, 4 * 2 * 3);
        // The web wallet's own independent vector (keys.test.ts).
        let (legacy, legacy_seed) = legacy_material(&core::array::from_fn(|i| i as u8)).unwrap();
        assert_eq!(hex::encode(legacy.to_secret_bytes()), "2176887b814d6b1ea71118d2ec33d1daa3aab5c28c03fcd691143e292606d69e");
        assert_eq!(hex::encode(*legacy_seed), "20ac24f76ddb96f72d70892a38a8d0b536c27834dddbfc8efc51ea066a2513ad");
    }

    #[test]
    fn legacy_keys_match_the_web_wallet() {
        for k in vectors()["keys"].as_array().unwrap() {
            let restored = Secret::from_backup_code(k["backup"].as_str().unwrap()).unwrap();
            assert!(matches!(&restored, Secret::Legacy { seed } if seed.0.to_vec() == h(&k["seed"])));
            assert_eq!(restored.recovery_text().as_str(), k["backup"].as_str().unwrap());
            let keys = Keys::from_secret(&restored).unwrap();
            assert_eq!(hex::encode(keys.schnorr.xonly.to_byte_array()), k["xonly"].as_str().unwrap());
            assert_eq!(hex::encode(Sha256::digest(keys.mldsa44.secret.as_bytes())), k["mldsa44_secret_key_sha256"].as_str().unwrap());
            // As in the web wallet, every template of a backup code's wallet uses the same two keys.
            assert_eq!(keys.mixed_schnorr.xonly, keys.schnorr.xonly);
            assert_eq!(keys.mixed_mldsa44.public, keys.mldsa44.public);
        }
    }

    #[test]
    fn templates_of_new_wallets_share_no_key() {
        let keys = Keys::from_secret(&bip39([0u8; 32])).unwrap();
        assert_ne!(keys.schnorr.xonly, keys.mixed_schnorr.xonly);
        assert_ne!(keys.mldsa44.public, keys.mixed_mldsa44.public);
        let mixed = keys.template(Kind::Mixed);
        assert_eq!(mixed.schnorr_leaf.as_ref().unwrap().script[1..33], keys.mixed_schnorr.xonly.to_byte_array());
        assert_ne!(keys.template(Kind::Schnorr).address, mixed.address);
    }

    #[test]
    fn pq2_keys_are_fresh_per_index_and_chain_and_absent_for_backup_codes() {
        let keys = Keys::from_secret(&bip39([5u8; 32])).unwrap();
        let mut seen = std::collections::HashSet::new();
        for chain in [RECEIVE_CHAIN, CHANGE_CHAIN] {
            for index in 0..3 {
                let p = keys.pq2(chain, index).unwrap();
                assert!(seen.insert(*p.slhdsa128s_public_key()));
                assert!(seen.insert(p.mldsa44_public_key()[..32].try_into().unwrap()));
                assert!(seen.insert(p.template().root));
            }
        }
        // None of them is a key of the fixed templates.
        let fixed: [u8; 32] = keys.mldsa44.public[..32].try_into().unwrap();
        assert!(!seen.contains(&fixed));
        assert_eq!(keys.pq2(2, 0).err(), Some(KeyError::Pq2Unavailable));
        let legacy = Keys::from_secret(&Secret::from_backup_code("ark0w1-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f-630dcd29").unwrap()).unwrap();
        assert!(!legacy.has_pq2() && keys.has_pq2());
        assert_eq!(legacy.pq2(0, 0).err(), Some(KeyError::Pq2Unavailable));
        // Signatures of both leaves verify (they are checked before they are returned).
        let p = keys.pq2(0, 0).unwrap();
        let message = [9u8; 32];
        assert!(slhdsa::verify(&p.sign_slhdsa128s(&message).unwrap(), &message, SLHDSA128S_CONTEXT, p.slhdsa128s_public_key()));
        assert!(mldsa::verify(&p.sign_mldsa44(&message).unwrap(), &message, MLDSA44_CONTEXT, p.mldsa44_public_key()));
    }

    /// SHA-512 over the core type is SHA-512, at every length around the block boundaries.
    #[test]
    fn sha512_over_the_core_is_sha512() {
        let data: Vec<u8> = (0..400u32).map(|i| (i * 7 + 3) as u8).collect();
        for n in [0, 1, 111, 112, 127, 128, 129, 255, 256, 257, 400] {
            let mut out = [0u8; 64];
            sha512_into(&[&data[..n / 3], &data[n / 3..n]], &mut out);
            assert_eq!(out[..], Sha512::digest(&data[..n])[..], "{n} bytes");
        }
    }

    /// RFC 4231's HMAC-SHA-512 test cases 1, 2, 3, 6 and 7 (a key longer than the block is hashed first).
    #[test]
    fn hmac_sha512_matches_rfc_4231() {
        let cases: [(Vec<u8>, Vec<u8>, &str); 5] = [
            (vec![0x0b; 20], b"Hi There".to_vec(), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
            (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
            (vec![0xaa; 20], vec![0xdd; 50], "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
            (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(), "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
            (vec![0xaa; 131], b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(), "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"),
        ];
        for (key, data, want) in cases {
            let mut out = [0u8; 64];
            hmac_sha512_into(&key, &[&data[..3.min(data.len())], &data[3.min(data.len())..]], &mut out);
            assert_eq!(hex::encode(out), want);
        }
    }

    /// The hash and MAC states and outputs the derivation goes through are wiped when they are dropped:
    /// this only builds with the zeroize features of sha2 and hmac enabled.
    #[test]
    fn derivation_states_wipe_themselves() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<sha2::block_api::Sha512VarCore>();
        wiped_on_drop::<<Sha512 as hmac::digest::block_api::CoreProxy>::Core>();
        wiped_on_drop::<<Sha256 as hmac::digest::block_api::CoreProxy>::Core>();
        wiped_on_drop::<hmac::digest::CtOutput<Hmac<Sha512>>>();
        wiped_on_drop::<hmac::digest::block_api::Buffer<<Sha512 as hmac::digest::block_api::CoreProxy>::Core>>();
        // Several blocks of Expand (RFC 5869 T(1) || T(2) || ...) agree with one long output's prefix.
        let seed = [3u8; 64];
        let (mut long, mut short) = ([0u8; 200], [0u8; 48]);
        hkdf_sha512(&seed, b"info", &mut long);
        hkdf_sha512(&seed, b"info", &mut short);
        assert_eq!(long[..48], short);
    }

    #[test]
    fn backup_codes_forgive_layout_but_not_typos() {
        let code = "ark0w1-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f-630dcd29";
        let messy = format!("  {}\n {} \t{} ", code[..30].to_uppercase(), &code[30..60], &code[60..]);
        assert!(Secret::from_backup_code(&messy).is_ok());
        let typo = format!("{}{}{}", &code[..10], if &code[10..11] == "0" { "1" } else { "0" }, &code[11..]);
        assert_eq!(Secret::from_backup_code(&typo).err(), Some(KeyError::InvalidBackupCode));
        assert_eq!(Secret::from_backup_code(&code.replace("ark0w1-", "ark0w2-")).err(), Some(KeyError::InvalidBackupCode));
        assert_eq!(Secret::from_backup_code("").err(), Some(KeyError::InvalidBackupCode));
        assert!(looks_like_backup_code(&messy) && looks_like_backup_code("ARK0W1") && !looks_like_backup_code("abandon ark0w1"));
    }

    #[test]
    fn new_wallet_randomness_is_fallible() {
        let failed = Secret::new_bip39_with(|bytes| {
            bytes[..8].fill(7);
            Err(())
        });
        assert_eq!(failed.err(), Some(KeyError::Randomness));
        assert_eq!(serde_json::to_string(&KeyError::Randomness).unwrap(), "\"randomness\"");
        let secret = Secret::new_bip39_with(|bytes| {
            bytes.fill(9);
            Ok::<(), ()>(())
        }).unwrap();
        assert!(matches!(secret, Secret::Bip39 { entropy } if *entropy.0 == [9; 32]));
    }

    #[test]
    fn phrases_round_trip() {
        let zero = bip39([0u8; 32]);
        let words = zero.recovery_text();
        assert_eq!(words.as_str(), [["abandon"; 23].join(" ").as_str(), "art"].join(" "));
        let back = Secret::from_phrase(&format!("  {}  ", words.to_uppercase())).unwrap();
        assert!(matches!(&back, Secret::Bip39 { entropy } if *entropy.0 == [0u8; 32]));
        assert_eq!(Secret::from_phrase("abandon abandon").err(), Some(KeyError::InvalidPhrase));
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(Secret::from_phrase(twelve).err(), Some(KeyError::InvalidPhrase));
        let fresh = Secret::new_bip39().unwrap();
        let again = Secret::from_phrase(&fresh.recovery_text()).unwrap();
        for kind in [Kind::Schnorr, Kind::Mldsa44, Kind::Mixed] {
            assert_eq!(Keys::from_secret(&fresh).unwrap().template(kind).address, Keys::from_secret(&again).unwrap().template(kind).address);
        }
    }

    #[test]
    fn signatures_verify() {
        let keys = Keys::from_secret(&Secret::new_bip39().unwrap()).unwrap();
        let message = [7u8; 32];
        for kind in [Kind::Schnorr, Kind::Mixed] {
            let sig = schnorr::Signature::from_byte_array(keys.sign_schnorr(kind, &message).unwrap());
            assert!(schnorr::verify(&sig, &message, &keys.schnorr_key(kind).xonly).is_ok());
        }
        for kind in [Kind::Mldsa44, Kind::Mixed] {
            let pq = keys.sign_mldsa44(kind, &message).unwrap();
            assert!(mldsa::verify(&pq, &message, MLDSA44_CONTEXT, &keys.mldsa44_key(kind).public));
        }
    }
}
