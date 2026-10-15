fn main() {
    // mldsa-native, portable C only, one translation unit (csrc/README.md).
    println!("cargo:rerun-if-changed=csrc");
    cc::Build::new()
        .file("csrc/pqw_mldsa44.c")
        .include("csrc")
        .include("csrc/mldsa-native")
        .warnings(false)
        .compile("pqw_mldsa44");
    tauri_build::build()
}
