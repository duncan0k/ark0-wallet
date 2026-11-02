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

/// The deterministic variant (opt_rand = PK.seed). Used only to reproduce test vectors byte for byte; the
/// wallet signs with `sign`.
#[cfg(test)]
pub fn sign_deterministic(message: &[u8], context: &[u8], secret: &SecretKey) -> Result<Box<[u8; SIGNATURE_LEN]>, Error> {
    sign_with(message, context, secret, None)
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

#[cfg(test)]
mod tests {
    use super::*;
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
            sign_deterministic(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap()[..],
            sign_deterministic(&message, SLHDSA128S_CONTEXT, &pair.secret).unwrap()[..]
        );
    }
}
