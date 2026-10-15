//! ML-DSA-44 (FIPS 204) through the vendored mldsa-native library (csrc/).
//!
//! Signatures here are the pure, external-interface ML-DSA that the Ark-0 node checks: the message is
//! signed together with a context string, M' = 0x00 || len(ctx) || ctx || M.

use std::os::raw::c_int;
use zeroize::Zeroize;

pub const PUBLIC_KEY_LEN: usize = 1312;
pub const SECRET_KEY_LEN: usize = 2560;
pub const SIGNATURE_LEN: usize = 2420;
pub const SEED_LEN: usize = 32;

extern "C" {
    fn pqw_mldsa_keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
    fn pqw_mldsa_signature_internal(
        sig: *mut u8,
        m: *const u8,
        mlen: usize,
        pre: *const u8,
        prelen: usize,
        rnd: *const u8,
        sk: *const u8,
        externalmu: c_int,
    ) -> c_int;
    fn pqw_mldsa_signature(sig: *mut u8, m: *const u8, mlen: usize, ctx: *const u8, ctxlen: usize, sk: *const u8) -> c_int;
    fn pqw_mldsa_verify(sig: *const u8, m: *const u8, mlen: usize, ctx: *const u8, ctxlen: usize, pk: *const u8) -> c_int;
}

/// The randomness mldsa-native asks for when it signs (csrc/pqw_mldsa44_config.h). A failure is
/// reported as nonzero, and the library then fails the signature instead of signing without it.
#[no_mangle]
pub extern "C" fn pqw_randombytes(out: *mut u8, outlen: usize) -> c_int {
    if outlen == 0 {
        return 0;
    }
    if out.is_null() {
        return -1;
    }
    // SAFETY: mldsa-native passes a buffer of exactly outlen writable bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(out, outlen) };
    match getrandom::fill(buf) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The context string is longer than the 255 bytes FIPS 204 allows.
    ContextTooLong,
    /// The library returned an error code.
    Library(c_int),
}

pub struct SecretKey(Box<[u8; SECRET_KEY_LEN]>);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct KeyPair {
    pub public: Box<[u8; PUBLIC_KEY_LEN]>,
    pub secret: SecretKey,
}

/// FIPS 204 ML-DSA.KeyGen_internal(xi): the key pair a 32-byte seed determines.
pub fn keypair_from_seed(seed: &[u8; SEED_LEN]) -> Result<KeyPair, Error> {
    let mut public = Box::new([0u8; PUBLIC_KEY_LEN]);
    let mut secret = SecretKey(Box::new([0u8; SECRET_KEY_LEN]));
    // SAFETY: the buffers have the sizes the ML-DSA-44 build of the library writes and reads.
    let rc = unsafe { pqw_mldsa_keypair_internal(public.as_mut_ptr(), secret.0.as_mut_ptr(), seed.as_ptr()) };
    if rc != 0 {
        return Err(Error::Library(rc));
    }
    Ok(KeyPair { public, secret })
}

/// Hedged signing (FIPS 204 default): fresh randomness from the operating system for every signature.
pub fn sign(message: &[u8], context: &[u8], secret: &SecretKey) -> Result<[u8; SIGNATURE_LEN], Error> {
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    // SAFETY: pointer and length pairs describe live buffers; sizes as above.
    let rc = unsafe {
        pqw_mldsa_signature(sig.as_mut_ptr(), message.as_ptr(), message.len(), context.as_ptr(), context.len(), secret.0.as_ptr())
    };
    if rc != 0 {
        return Err(Error::Library(rc));
    }
    Ok(sig)
}

/// The deterministic variant (rnd = 0^32). Used only to reproduce test vectors byte for byte; the wallet
/// signs with `sign`.
pub fn sign_deterministic(message: &[u8], context: &[u8], secret: &SecretKey) -> Result<[u8; SIGNATURE_LEN], Error> {
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    let mut pre = Vec::with_capacity(2 + context.len());
    pre.push(0u8);
    pre.push(context.len() as u8);
    pre.extend_from_slice(context);
    let rnd = [0u8; 32];
    let mut sig = [0u8; SIGNATURE_LEN];
    // SAFETY: as above; externalmu = 0 means `message` is the message itself, not a precomputed mu.
    let rc = unsafe {
        pqw_mldsa_signature_internal(
            sig.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            pre.as_ptr(),
            pre.len(),
            rnd.as_ptr(),
            secret.0.as_ptr(),
            0,
        )
    };
    if rc != 0 {
        return Err(Error::Library(rc));
    }
    Ok(sig)
}

pub fn verify(signature: &[u8; SIGNATURE_LEN], message: &[u8], context: &[u8], public: &[u8; PUBLIC_KEY_LEN]) -> bool {
    if context.len() > 255 {
        return false;
    }
    // SAFETY: as above.
    let rc = unsafe {
        pqw_mldsa_verify(signature.as_ptr(), message.as_ptr(), message.len(), context.as_ptr(), context.len(), public.as_ptr())
    };
    rc == 0
}
