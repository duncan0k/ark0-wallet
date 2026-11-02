//! SLH-DSA-SHA2-128s (FIPS 205) through the vendored slhdsa-c library (csrc/).
//!
//! Signatures here are the pure, external-interface SLH-DSA that OP_CHECKSLHDSA128S checks: the message
//! is signed together with a context string, M' = 0x00 || len(ctx) || ctx || M. Every length is fixed by
//! the types before the library sees a buffer (the library reads a signature before it checks its size).

use std::os::raw::c_int;
use zeroize::Zeroize;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 7856;
/// SK.seed || SK.prf || PK.seed, 16 bytes each.
pub const SEED_LEN: usize = 48;
/// opt_rand: n bytes of fresh randomness per signature.
const RANDOMNESS_LEN: usize = 16;

extern "C" {
    fn pqw_slhdsa128s_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
    fn pqw_slhdsa128s_sign(sig: *mut u8, m: *const u8, mlen: usize, ctx: *const u8, ctxlen: usize, sk: *const u8, addrnd: *const u8) -> c_int;
    fn pqw_slhdsa128s_verify(sig: *const u8, m: *const u8, mlen: usize, ctx: *const u8, ctxlen: usize, pk: *const u8) -> c_int;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The context string is longer than the 255 bytes FIPS 205 allows.
    ContextTooLong,
    /// The system could not provide the signing randomness.
    Randomness,
    /// The library returned an error code.
    Library(c_int),
}

/// SK.seed, SK.prf, PK.seed and PK.root; wiped when dropped.
pub struct SecretKey(Box<[u8; SECRET_KEY_LEN]>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct KeyPair {
    pub public: [u8; PUBLIC_KEY_LEN],
    pub secret: SecretKey,
}

/// FIPS 205 slh_keygen_internal(SK.seed, SK.prf, PK.seed) on the three 16-byte parts of `seed`:
/// [0, 16), [16, 32) and [32, 48).
pub fn keypair_from_seed(seed: &[u8; SEED_LEN]) -> Result<KeyPair, Error> {
    let mut public = [0u8; PUBLIC_KEY_LEN];
    let mut secret = SecretKey(Box::new([0u8; SECRET_KEY_LEN]));
    // SAFETY: the buffers have the sizes the SHA2-128s parameter set writes and reads (the wrapper checks
    // the library agrees).
    let rc = unsafe { pqw_slhdsa128s_keypair(public.as_mut_ptr(), secret.0.as_mut_ptr(), seed.as_ptr()) };
    if rc != 0 {
        return Err(Error::Library(rc));
    }
    Ok(KeyPair { public, secret })
}

fn sign_with(message: &[u8], context: &[u8], secret: &SecretKey, randomness: Option<&[u8; RANDOMNESS_LEN]>) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    let mut sig = Box::new([0u8; SIGNATURE_LEN]);
    let addrnd = randomness.map_or(std::ptr::null(), |r| r.as_ptr());
    // SAFETY: pointer and length pairs describe live buffers; the signature buffer is 7,856 bytes, the
    // secret key 64, and addrnd is null or 16 bytes.
    let rc = unsafe {
        pqw_slhdsa128s_sign(sig.as_mut_ptr(), message.as_ptr(), message.len(), context.as_ptr(), context.len(), secret.0.as_ptr(), addrnd)
    };
    if rc != 0 {
        return Err(Error::Library(rc));
    }
    Ok(sig)
}

/// Hedged signing (FIPS 205 default): 16 bytes of fresh randomness from the operating system as opt_rand.
pub fn sign(message: &[u8], context: &[u8], secret: &SecretKey) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    let mut randomness = [0u8; RANDOMNESS_LEN];
    getrandom::fill(&mut randomness).map_err(|_| Error::Randomness)?;
    let result = sign_with(message, context, secret, Some(&randomness));
    randomness.zeroize();
    result
}

/// With a given opt_rand, to reproduce a hedged test vector.
#[cfg(test)]
pub fn sign_with_randomness(message: &[u8], context: &[u8], secret: &SecretKey, randomness: &[u8; RANDOMNESS_LEN]) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    sign_with(message, context, secret, Some(randomness))
}

pub fn verify(signature: &[u8; SIGNATURE_LEN], message: &[u8], context: &[u8], public: &[u8; PUBLIC_KEY_LEN]) -> bool {
    if context.len() > 255 {
        return false;
    }
    // SAFETY: as above; the signature is exactly 7,856 bytes and the key 32, so the library never reads
    // past either.
    let rc = unsafe { pqw_slhdsa128s_verify(signature.as_ptr(), message.as_ptr(), message.len(), context.as_ptr(), context.len(), public.as_ptr()) };
    rc == 0
}

/// Known answers from an independent implementation (p2mr-ts with @noble/post-quantum 0.7.1, its M4
/// vectors): seed, public key; and for the first, a message and the SHA-256 of its deterministic signature
/// with OP_CHECKSLHDSA128S's context. A build with the wrong byte order gets every one of them wrong.
pub const KAT_KEYS: [(&str, &str); 3] = [
    (
        "d1a914a61630a183ff238cd37b4b8f8d44685573cde337c04a3e57ca1090f2412403aff2966abd00377cc0a1791b5163",
        "2403aff2966abd00377cc0a1791b5163532756d0b79b4d1c24be1b3830cfa535",
    ),
    (
        "02d8ae9f631f168961bee809f50a64e37c6c3bd0f222dc289946b6bd5a2246678a01c204fb7af8f5fc9da3a8f9c62a6d",
        "8a01c204fb7af8f5fc9da3a8f9c62a6d7c89185b287f18e53e93c2e7b7ec3c17",
    ),
    (
        "f8160ee5a953c43d28b3be4a85475bcf00cd040d2300be4272d1733e9b6c900388d1801ea9c2caf67fd6e4198dd19eba",
        "88d1801ea9c2caf67fd6e4198dd19eba18220f7064dea4afcd39085cc59bd1d2",
    ),
];
/// Key B (the second above) signs this message deterministically; the signature's SHA-256.
pub const KAT_MESSAGE: &str = "2ff4487eee01ffc57e04b3f20f5cc0887523a609c218f823af7057cc46577d1f";
pub const KAT_SIGNATURE_SHA256: &str = "f46d95ecffe77ea332b7b56ba67036677b24e4a962ea5b837cd5d99a02ce4bc9";

/// The deterministic variant, for the known-answer checks (the self-test and the tests); the wallet signs
/// with `sign`.
pub fn sign_known_answer(message: &[u8], context: &[u8], secret: &SecretKey) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    sign_with(message, context, secret, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn known_answers_of_an_independent_implementation() {
        for (seed, public) in KAT_KEYS {
            let pair = keypair_from_seed(&hex::decode(seed).unwrap().try_into().unwrap()).unwrap();
            assert_eq!(hex::encode(pair.public), public);
        }
        let pair = keypair_from_seed(&hex::decode(KAT_KEYS[1].0).unwrap().try_into().unwrap()).unwrap();
        let message = hex::decode(KAT_MESSAGE).unwrap();
        let sig = sign_known_answer(&message, b"P2MR/SLHDSA128S/EXP0", &pair.secret).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&sig[..])), KAT_SIGNATURE_SHA256);
        assert!(verify(&sig, &message, b"P2MR/SLHDSA128S/EXP0", &pair.public));
    }
    const SLHDSA128S_CONTEXT: &[u8] = b"P2MR/SLHDSA128S/EXP0";

    #[test]
    fn signs_and_verifies_and_refuses_what_it_should() {
        let pair = keypair_from_seed(&[7u8; SEED_LEN]).unwrap();
        // PK.seed is the last 16 bytes of the seed.
        assert_eq!(pair.public[..16], [7u8; 16]);
        let message = [1u8; 32];
        let sig = sign(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap();
        assert!(verify(&sig, &message, SLHDSA128S_CONTEXT, &pair.public));
        // Hedged: two signatures of the same message differ, and both verify.
        let again = sign(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap();
        assert_ne!(sig[..], again[..]);
        assert!(verify(&again, &message, SLHDSA128S_CONTEXT, &pair.public));
        // Another message, another context, a flipped bit, another key.
        assert!(!verify(&sig, &[2u8; 32], SLHDSA128S_CONTEXT, &pair.public));
        assert!(!verify(&sig, &message, b"P2MR/MLDSA44/EXP0", &pair.public));
        let mut bad = sig.clone();
        bad[SIGNATURE_LEN - 1] ^= 1;
        assert!(!verify(&bad, &message, SLHDSA128S_CONTEXT, &pair.public));
        let other = keypair_from_seed(&[8u8; SEED_LEN]).unwrap();
        assert!(!verify(&sig, &message, SLHDSA128S_CONTEXT, &other.public));
        assert_eq!(sign(&message, &[0u8; 256], &pair.secret).err(), Some(Error::ContextTooLong));
        assert!(!verify(&sig, &message, &[0u8; 256], &pair.public));
        // The deterministic variant is reproducible.
        assert_eq!(
            sign_known_answer(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap()[..],
            sign_known_answer(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap()[..]
        );
    }
}
