//! Self-test of the native signing core, run on every platform the app is built for.
//!
//! The expected values were computed with the libraries the web wallet and p2mr-ts sign with
//! (@noble/post-quantum 0.7.1, @noble/curves 2.4.0); the BIP-340 one is test vector 1 of the BIP. Matching
//! them byte for byte shows that mldsa-native (the library the Ark-0 node verifies with) and libsecp256k1
//! produce exactly what the existing wallet produces, on this CPU and with this compiler.

use crate::mldsa;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;

/// FIPS 204 context string of every signature OP_CHECKMLDSA44 checks on Ark-0.
pub const P2MR_MLDSA44_CONTEXT: &[u8] = b"P2MR/MLDSA44/EXP0";

const MLDSA_PK_SHA256: &str = "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46";
const MLDSA_SK_SHA256: &str = "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b";
const MLDSA_SIG_DET_SHA256: &str = "5a80a821448cac382d090afd66d97583dbe68c3e32460abbdca8b7326266d5f7";

const BIP340_SK: &str = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";
const BIP340_PK: &str = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const BIP340_AUX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const BIP340_MSG: &str = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89";
const BIP340_SIG: &str = "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a";

#[derive(Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct Timing {
    pub name: &'static str,
    pub median_ms: f64,
    pub runs: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub ok: bool,
    pub version: &'static str,
    pub target: String,
    pub checks: Vec<Check>,
    pub timings: Vec<Timing>,
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data).as_slice())
}

fn bytes32(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).expect("a constant of 32 bytes");
    out
}

/// Median time of `runs` calls of `f`, in milliseconds rounded to the microsecond.
fn measure(name: &'static str, runs: usize, mut f: impl FnMut()) -> Timing {
    let mut samples: Vec<f64> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Timing { name, median_ms: (samples[samples.len() / 2] * 1000.0).round() / 1000.0, runs }
}

fn check(checks: &mut Vec<Check>, name: &'static str, ok: bool, detail: impl Into<String>) {
    checks.push(Check { name, ok, detail: detail.into() });
}

pub fn run() -> Report {
    let mut checks = Vec::new();
    let mut timings = Vec::new();

    // --- ML-DSA-44 ---
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut message = [0u8; 32];
    message.copy_from_slice(Sha256::digest(b"pq-wallet selftest message").as_slice());
    match mldsa::keypair_from_seed(&seed) {
        Err(e) => check(&mut checks, "mldsa44_keygen_vector", false, format!("keygen failed: {e:?}")),
        Ok(kp) => {
            let pk_ok = sha256_hex(&kp.public[..]) == MLDSA_PK_SHA256;
            let sk_ok = sha256_hex(kp.secret.as_bytes()) == MLDSA_SK_SHA256;
            check(&mut checks, "mldsa44_keygen_vector", pk_ok && sk_ok, format!("public key {}, secret key {}", ok_word(pk_ok), ok_word(sk_ok)));

            match mldsa::sign_deterministic(&message, P2MR_MLDSA44_CONTEXT, &kp.secret) {
                Err(e) => check(&mut checks, "mldsa44_deterministic_signature_vector", false, format!("{e:?}")),
                Ok(sig) => {
                    let same = sha256_hex(&sig) == MLDSA_SIG_DET_SHA256;
                    check(&mut checks, "mldsa44_deterministic_signature_vector", same, "byte-identical to @noble/post-quantum 0.7.1".to_string());
                    let valid = mldsa::verify(&sig, &message, P2MR_MLDSA44_CONTEXT, &kp.public);
                    check(&mut checks, "mldsa44_verify", valid, "the vector signature verifies");
                    let mut other = message;
                    other[0] ^= 1;
                    let rejects_message = !mldsa::verify(&sig, &other, P2MR_MLDSA44_CONTEXT, &kp.public);
                    let rejects_context = !mldsa::verify(&sig, &message, b"P2MR/MLDSA44/EXP1", &kp.public);
                    let mut bad = sig;
                    bad[100] ^= 0x10;
                    let rejects_signature = !mldsa::verify(&bad, &message, P2MR_MLDSA44_CONTEXT, &kp.public);
                    check(
                        &mut checks,
                        "mldsa44_rejects_tampering",
                        rejects_message && rejects_context && rejects_signature,
                        format!("changed message {}, other context {}, changed signature {}", ok_word(rejects_message), ok_word(rejects_context), ok_word(rejects_signature)),
                    );
                }
            }

            match (mldsa::sign(&message, P2MR_MLDSA44_CONTEXT, &kp.secret), mldsa::sign(&message, P2MR_MLDSA44_CONTEXT, &kp.secret)) {
                (Ok(a), Ok(b)) => {
                    let valid = mldsa::verify(&a, &message, P2MR_MLDSA44_CONTEXT, &kp.public) && mldsa::verify(&b, &message, P2MR_MLDSA44_CONTEXT, &kp.public);
                    check(&mut checks, "mldsa44_hedged_signing", valid && a != b, format!("two hedged signatures {}, distinct {}", ok_word(valid), ok_word(a != b)));
                }
                (a, b) => check(&mut checks, "mldsa44_hedged_signing", false, format!("{:?} {:?}", a.err(), b.err())),
            }

            timings.push(measure("mldsa44_keygen", 20, || {
                let _ = mldsa::keypair_from_seed(&seed);
            }));
            timings.push(measure("mldsa44_sign", 30, || {
                let _ = mldsa::sign(&message, P2MR_MLDSA44_CONTEXT, &kp.secret);
            }));
            let sig = mldsa::sign(&message, P2MR_MLDSA44_CONTEXT, &kp.secret).unwrap_or([0u8; mldsa::SIGNATURE_LEN]);
            timings.push(measure("mldsa44_verify", 50, || {
                let _ = mldsa::verify(&sig, &message, P2MR_MLDSA44_CONTEXT, &kp.public);
            }));
        }
    }

    // --- BIP-340 Schnorr (libsecp256k1) ---
    match secp256k1::Keypair::from_secret_bytes(bytes32(BIP340_SK)) {
        Err(e) => check(&mut checks, "schnorr_bip340_vector", false, format!("{e}")),
        Ok(keypair) => {
            let (xonly, _) = keypair.x_only_public_key();
            let msg = bytes32(BIP340_MSG);
            let aux = bytes32(BIP340_AUX);
            let sig = secp256k1::schnorr::sign_with_aux_rand(&msg, &keypair, &aux);
            let pk_ok = xonly.to_string() == BIP340_PK;
            let sig_ok = sig.to_string() == BIP340_SIG;
            check(&mut checks, "schnorr_bip340_vector", pk_ok && sig_ok, format!("public key {}, signature {}", ok_word(pk_ok), ok_word(sig_ok)));
            let valid = secp256k1::schnorr::verify(&sig, &msg, &xonly).is_ok();
            let mut other = msg;
            other[31] ^= 1;
            let rejects = secp256k1::schnorr::verify(&sig, &other, &xonly).is_err();
            check(&mut checks, "schnorr_verify", valid && rejects, format!("verifies {}, rejects a changed message {}", ok_word(valid), ok_word(rejects)));
            timings.push(measure("schnorr_sign", 50, || {
                let _ = secp256k1::schnorr::sign_with_aux_rand(&msg, &keypair, &aux);
            }));
            timings.push(measure("schnorr_verify", 50, || {
                let _ = secp256k1::schnorr::verify(&sig, &msg, &xonly);
            }));
        }
    }

    // --- the operating system's random generator, as mldsa-native sees it ---
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    let ra = mldsa::pqw_randombytes(a.as_mut_ptr(), a.len());
    let rb = mldsa::pqw_randombytes(b.as_mut_ptr(), b.len());
    check(&mut checks, "os_randomness", ra == 0 && rb == 0 && a != b && a != [0u8; 32], "two 32-byte draws succeed and differ");

    Report {
        ok: checks.iter().all(|c| c.ok),
        version: env!("CARGO_PKG_VERSION"),
        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        checks,
        timings,
    }
}

fn ok_word(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "MISMATCH"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        let report = super::run();
        for c in &report.checks {
            assert!(c.ok, "{}: {}", c.name, c.detail);
        }
        assert!(report.ok);
    }
}
