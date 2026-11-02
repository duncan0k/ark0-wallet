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
    // (csrc/README.md). The same plain C on every compiler: MSVC, clang and the Android NDK. The library
    // picks its byte swaps from __BYTE_ORDER__, which MSVC does not define: pqw_slh_byteorder.h, included
    // before every file, defines it there, refuses compilers it cannot tell, and checks it against the
    // target's byte order as Cargo knows it.
    let mut slh = cc::Build::new();
    let header = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("set by Cargo")).join("csrc/pqw_slh_byteorder.h");
    let header = header.to_str().expect("a UTF-8 path");
    if slh.get_compiler().is_like_msvc() {
        slh.flag(format!("/FI{header}"));
    } else {
        slh.flag("-include").flag(header);
    }
    match std::env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("little") => slh.define("PQW_TARGET_LITTLE_ENDIAN", None),
        Ok("big") => slh.define("PQW_TARGET_BIG_ENDIAN", None),
        other => panic!("unknown target byte order {other:?}"),
    };
    slh.file("csrc/pqw_slhdsa128s.c")
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
