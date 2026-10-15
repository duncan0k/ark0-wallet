# Vendored C code

`mldsa-native/` is [mldsa-native](https://github.com/pq-code-package/mldsa-native) v2.0.0, commit
`834a90d5e846ffa1e1611bd24e160bb2e9b86d35`, from the release tarball
`https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v2.0.0.tar.gz`
(SHA-256 `97a7305c32b62cbcae97891823176e18ca96d9eaafc3728587d75bb113862a40`). It implements FIPS 204
(ML-DSA) and is licensed Apache-2.0 OR ISC OR MIT; see `mldsa-native/LICENSE`.

What was taken, unmodified: `LICENSE`, `mldsa/mldsa_native.c`, `mldsa/mldsa_native.h`,
`mldsa/mldsa_native_config.h`, and the `.c`, `.h` and `.inc` files of `mldsa/src/` and
`mldsa/src/fips202/`. These are byte-for-byte the files the Ark-0 Bitcoin Core patch series vendors in
`src/crypto/mldsa44/`, so the wallet signs with the same library the node verifies with.

What was left out: the assembly backends (`mldsa/src/native/`, `mldsa/src/fips202/native/`) and
everything outside `mldsa/`. Only the portable C code is built, on every platform.

What was added: `pqw_mldsa44_config.h` (ML-DSA-44, the `pqw_mldsa` symbol prefix, randomness from
`pqw_randombytes`) and `pqw_mldsa44.c` (the translation unit `build.rs` compiles).

`scripts/check-vendor.sh` re-downloads the release tarball, checks its SHA-256 and compares every
vendored file with it.
