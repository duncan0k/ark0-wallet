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
//! This is not BIP-32: the 24 words open this wallet only. Typed into another wallet they give other
//! keys, and on an Ethereum wallet they would make a hot wallet of the words.
//!
//! A wallet of the Ark-0 web wallet holds a 32-byte seed, written down as an `ark0w1-…` backup code. Its
//! keys are derived as the web wallet derives them (keys.ts): the BIP-340 key is HMAC-SHA256 keyed with
//! `ark0-wallet v1 schnorr` over the seed and a counter byte, for the first counter from 0 that gives a
//! valid key; the ML-DSA-44 key is KeyGen on HMAC-SHA256 keyed with `ark0-wallet v1 mldsa44` over the seed.
//! As in the web wallet, its three templates share these two keys.
use crate::mldsa;
use crate::p2mr::{Kind, Template, MLDSA44_CONTEXT};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{schnorr, Keypair, XOnlyPublicKey};
use sha2::{Digest, Sha256, Sha512};
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
    /// No valid BIP-340 key within 256 attempts (each misses with a probability of about 2^-128).
    NoKey,
    /// A Schnorr signature could not be made, or did not verify.
    Schnorr,
    Mldsa44,
}

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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Secret {
    /// 24 words.
    Bip39 { entropy: SecretBytes },
    /// A wallet of the Ark-0 web wallet, restored from its backup code.
    Legacy { seed: SecretBytes },
}

impl Secret {
    pub fn new_bip39() -> Self {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).expect("the system's random source");
        Secret::Bip39 { entropy: SecretBytes(entropy) }
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

/// The template field of the HKDF info: the P2MR leaf version (0xc0 or 0xe0) and what the template holds.
fn template_label(kind: Kind) -> &'static [u8] {
    match kind {
        Kind::Schnorr => b"c0-schnorr",
        Kind::Mldsa44 => b"c0-mldsa44",
        Kind::Mixed => b"e0-hybrid",
    }
}

/// The HKDF info of one key. Account 0, the receiving chain and index 0: the one key of each leaf a
/// wallet uses so far; the fields are there so that more never collide with it.
fn key_info(network: &[u8; 32], algorithm: &[u8], kind: Kind, attempt: u8) -> Vec<u8> {
    let (account, chain, index) = (0u32, 0u32, 0u32);
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

/// The standard BIP-39 seed of 24 words, without a passphrase.
fn bip39_seed(entropy: &[u8; 32]) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy).map_err(|_| KeyError::InvalidPhrase)?;
    Ok(Zeroizing::new(mnemonic.to_seed_normalized("")))
}

/// 32 bytes for one key.
fn hkdf32(seed: &[u8; 64], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT), seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(label, out.as_mut()).expect("32 bytes is a valid HKDF-SHA-512 length");
    out
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
        out.copy_from_slice(&mac.finalize().into_bytes());
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
                })
            }
            Secret::Legacy { seed } => {
                let (schnorr, mldsa_seed) = legacy_material(&seed.0)?;
                Ok(Keys {
                    schnorr: SchnorrKey::new(schnorr),
                    mldsa44: keypair(&mldsa_seed)?,
                    mixed_schnorr: SchnorrKey::new(schnorr),
                    mixed_mldsa44: keypair(&mldsa_seed)?,
                })
            }
        }
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

    /// A template, made from its own keys.
    pub fn template(&self, kind: Kind) -> Template {
        match kind {
            Kind::Schnorr => Template::schnorr(&self.schnorr.xonly.to_byte_array()),
            Kind::Mldsa44 => Template::mldsa44(&self.mldsa44.public),
            Kind::Mixed => Template::mixed(&self.mixed_schnorr.xonly.to_byte_array(), &self.mixed_mldsa44.public),
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
    fn phrases_round_trip() {
        let zero = bip39([0u8; 32]);
        let words = zero.recovery_text();
        assert_eq!(words.as_str(), [["abandon"; 23].join(" ").as_str(), "art"].join(" "));
        let back = Secret::from_phrase(&format!("  {}  ", words.to_uppercase())).unwrap();
        assert!(matches!(&back, Secret::Bip39 { entropy } if *entropy.0 == [0u8; 32]));
        assert_eq!(Secret::from_phrase("abandon abandon").err(), Some(KeyError::InvalidPhrase));
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(Secret::from_phrase(twelve).err(), Some(KeyError::InvalidPhrase));
        let fresh = Secret::new_bip39();
        let again = Secret::from_phrase(&fresh.recovery_text()).unwrap();
        for kind in [Kind::Schnorr, Kind::Mldsa44, Kind::Mixed] {
            assert_eq!(Keys::from_secret(&fresh).unwrap().template(kind).address, Keys::from_secret(&again).unwrap().template(kind).address);
        }
    }

    #[test]
    fn signatures_verify() {
        let keys = Keys::from_secret(&Secret::new_bip39()).unwrap();
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
