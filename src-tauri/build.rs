fn main() {
    // mldsa-native, portable C only, one translation unit (csrc/README.md).
    println!("cargo:rerun-if-changed=csrc");
    cc::Build::new()
        .file("csrc/pqw_mldsa44.c")
        .include("csrc")
        .include("csrc/mldsa-native")
        .warnings(false)
        .compile("pqw_mldsa44");
    // slhdsa-c, its SHA-2 parameter sets and portable SHA-2 only, with the wallet's fixed-size wrapper
    // (csrc/README.md). The same plain C on every compiler: MSVC, clang and the Android NDK.
    cc::Build::new()
        .file("csrc/pqw_slhdsa128s.c")
        .file("csrc/slhdsa-c/slh_dsa.c")
        .file("csrc/slhdsa-c/slh_sha2.c")
        .file("csrc/slhdsa-c/sha2_256.c")
        .file("csrc/slhdsa-c/sha2_512.c")
        .include("csrc")
        .include("csrc/slhdsa-c")
        // Optimized in every profile: an SLH-DSA signature is millions of hash calls.
        .opt_level(2)
        .warnings(false)
        .compile("pqw_slhdsa128s");
    tauri_build::build()
}
